// proxy.go -- http proxy logic
package main

import (
    "io"
    "os"
    "fmt"
    "net"
    "time"
    "context"
    "syscall"
    "strings"
    "net/url"
    "net/http"
)

type Logger interface {
    Debug(fmt string, args ...interface{})
    Info(fmt string, args ...interface{})
    Warn(fmt string, args ...interface{})
    Error(fmt string, args ...interface{})
    URL(respCode int, url string, nr int64, t0, t1 time.Duration)
}

type HTTPProxy struct {
    // listen address
    addr    string

    // logger
    log     Logger

    // Transport for downstream connection
    tr      *http.Transport

    srv     *http.Server
}


func NewHTTPProxy(log Logger, addr string, tr *http.Transport) (*HTTPProxy, error) {
    p := &HTTPProxy{addr: addr, log: log}
    s := &http.Server{
            Addr: addr,
            Handler: p,
            ReadTimeout: 5 * time.Second,
            WriteTimeout: 10 * time.Second,
            MaxHeaderBytes: 1 << 20,
        }

    if tr == nil {
        tr = &http.Transport{}
    }

    p.srv = s
    p.tr  = tr

    return p, nil
}


// Start listener
func (p *HTTPProxy) Start() {

    go func() {
        p.log.Info("Starting HTTP proxy on %s ..", p.addr)
        if err := p.srv.ListenAndServe(); err != nil {
            die("Can't start proxy: %s\n%+v", err, err)
        }
    }()
}

// Stop server
// XXX Hijacked Websocket conns are not shutdown here
func (p *HTTPProxy) Stop() {
    cx, _ := context.WithTimeout(context.Background(), 10 * time.Second)

    p.srv.Shutdown(cx)
    p.log.Info("Listener %s shutdown", p.addr)
}


// XXX How do we handle websockets?
func (p *HTTPProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
    // XXX Error counts written somewhere?

    if r.Method == "CONNECT" {
        p.handleConnect(w, r)
        return
    }

    if !r.URL.IsAbs() {
        p.log.Debug("%s: non-proxy req for %q", r.Host, r.URL.String())
        http.Error(w, "No support for non-proxy requests", 500)
        return
    }

    t0 := time.Now()

    scrubReq(r)

    resp, err := p.tr.RoundTrip(r)
    if err != nil {
        p.log.Debug("%s: %s", r.Host, err)
        http.Error(w, err.Error(), 500)
        return
    }

    t1 := time.Now()

    copyHeaders(w.Header(), resp.Header)
    w.WriteHeader(resp.StatusCode)
    nr, _ := io.Copy(w, resp.Body)
    resp.Body.Close()

    t2 := time.Now()

    p.log.Debug("%s: %d %d %s %s\n", r.Host, resp.StatusCode, nr, t2.Sub(t0), r.URL.String())
    // Timing log
    p.log.URL(resp.StatusCode, r.URL.String(), nr, t1.Sub(t0), t2.Sub(t1))
}


var delHeaders = []string{
                    "Accept-Encoding",
                    "Proxy-Connection",
                    "Proxy-Authenticate",
                    "Proxy-Authorization",
                    "Connection",
                }

// Scrub the request and remove proxy headers
// XXX Do we add our own Via: or 
func scrubReq(r *http.Request) {
    for _, k := range delHeaders {
        r.Header.Del(k)
    }
}

// First delete the old headers and add the new ones
func copyHeaders(d, s http.Header) {
    // XXX Do we delete all _existing_ headers or only the ones that
    // are in 's' ?
    for k, _ := range s { d.Del(k) }

    for k, va := range s {
        for _, v := range va {
            d.Add(k, v)
        }
    }
}


// handle HTTP CONNECT
func (p *HTTPProxy) handleConnect(w http.ResponseWriter, r *http.Request) {
    
    h, ok := w.(http.Hijacker)
    if !ok {
        p.log.Warn("can't do CONNECT: hijack failed")
        http.Error(w, "Can't support CONNECT", 501)
        return
    }

    client, _, err := h.Hijack()
    if err != nil {
        // Likely HTTP/2.x -- its OK
        p.log.Warn("can't do CONNECT: hijack failed: %s", err)
        http.Error(w, "Can't support CONNECT", 501)
        client.Close()
        return
    }

    host := extractHost(r.URL)

    dest, err := p.dial("tcp", host)
    if err != nil {
        p.log.Debug("can't connect to %s: %s", host, err)
        http.Error(w, fmt.Sprintf("can't connect to %s", host), 500)
        client.Close()
        return
    }

    client.Write(_200Ok)

    s := client.(*net.TCPConn)
    d := dest.(*net.TCPConn)

    p.log.Debug("%s: CONNECT %s",
                s.RemoteAddr().String(), host)

    // XXX Do we just fork and return?

    go p.iocopy(d, s)
    go p.iocopy(s, d)
}

// Dial using the transport or built in
func (p *HTTPProxy) dial(netw, addr string) (net.Conn, error) {
    if p.tr.Dial != nil {
        return p.tr.Dial(netw, addr)
    }

    return net.Dial(netw, addr)
}

func isReset(err error) bool {
    if oe, ok := err.(*net.OpError); ok {
        if se, ok := oe.Err.(*os.SyscallError); ok {
            if se.Err == syscall.EPIPE || se.Err == syscall.ECONNRESET {
                return true
            }
        }
    }
    return false
}

// Copy from 's' to 'd'
func (p *HTTPProxy) iocopy(d, s *net.TCPConn) {
    _, err := io.Copy(d, s)
    if err != nil && err != io.EOF && !isReset(err) {
            p.log.Debug("copy from %s to %s: %s",
                        s.RemoteAddr().String(), d.RemoteAddr().String(), err)
    }

    d.CloseWrite()
    s.CloseRead()
}

func extractHost(u *url.URL) string {
    h := u.Host

    i := strings.LastIndex(h, ":")
    if i < 0  {
        h += ":80"
    }
    return h
}

// used when we hijack for CONNECT
var _200Ok []byte = []byte("HTTP/1.0 200 OK\r\n\r\n")

