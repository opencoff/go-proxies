// proxy.go -- http proxy logic
//
// Author: Sudhi Herle <sudhi@herle.net>
//
// This software does not come with any express or implied
// warranty; it is provided "as is". No claim  is made to its
// suitability for any purpose.

package main

import (
    "io"
    "fmt"
    "net"
    "sync"
    "time"
    "context"
    "strings"
    "net/url"
    "net/http"

	L "github.com/opencoff/go-lib/logger"
	"github.com/opencoff/go-lib/ratelimit"
)


type HTTPProxy struct {
    *net.TCPListener

    // listen address
    conf    *ListenConf

    stop  chan bool
    wg    sync.WaitGroup

    rl   *ratelimit.Ratelimiter

    // logger
    log     *L.Logger
    ulog    *L.Logger

    // Transport for downstream connection
    tr      *http.Transport

    srv     *http.Server
}


func NewHTTPProxy(lc *ListenConf, log, ulog *L.Logger) (Proxy, error) {
    addr    := lc.Listen
    la, err := net.ResolveTCPAddr("tcp", addr)
    if err != nil {
        die("Can't resolve %s: %s", addr, err)
    }

    ln, err := net.ListenTCP("tcp", la)
    if err != nil {
        die("Can't listen on %s: %s", addr, err)
    }

    p := &HTTPProxy{conf: lc, log: log, ulog: ulog, stop: make(chan bool)}
    s := &http.Server{
            Addr: addr,
            Handler: p,
            ReadTimeout: 5 * time.Second,
            WriteTimeout: 10 * time.Second,
            MaxHeaderBytes: 1 << 20,
        }

    // Conf file specifies ratelimit as N conns/sec
    rl, err := ratelimit.New(lc.Ratelimit, 1)

    p.TCPListener = ln
    p.srv = s
    p.rl  = rl
    p.tr  = &http.Transport{}

    log.Info("HTTP listening on %s ..", lc.Listen)
    return p, nil
}


// Start listener
func (p *HTTPProxy) Start() {

    p.wg.Add(1)
    go func() {
        defer p.wg.Done()
        p.log.Info("Starting HTTP proxy on %s ..", p.conf.Listen)
        p.srv.Serve(p)
    }()
}



// Stop server
// XXX Hijacked Websocket conns are not shutdown here
func (p *HTTPProxy) Stop() {
    close(p.stop)

    cx, _ := context.WithTimeout(context.Background(), 10 * time.Second)
    p.srv.Shutdown(cx)

    p.wg.Wait()
    p.log.Info("HTTP proxy on %s shutdown", p.conf.Listen)
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

    copyRespHeaders(w.Header(), resp.Header)
    w.WriteHeader(resp.StatusCode)
    nr, _ := io.Copy(w, resp.Body)
    resp.Body.Close()

    t2 := time.Now()

    p.log.Debug("%s: %d %d %s %s\n", r.Host, resp.StatusCode, nr, t2.Sub(t0), r.URL.String())
    // Timing log
    if p.ulog != nil {
        d0 := format(t1.Sub(t0))
        d1 := format(t2.Sub(t1))

        now := time.Now().UTC().Format(time.RFC3339)

        p.ulog.Info("time=%q url=%q status=\"%d\" bytes=\"%d\" upstream=%q downstream=%q",
                        now, r.URL.String(), resp.StatusCode, nr, d0, d1)
    }
}


func extractHost(u *url.URL) string {
    h := u.Host

    i := strings.LastIndex(h, ":")
    if i < 0  {
        h += ":80"
    }
    return h
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

    if clientIP, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
        // If we aren't the first proxy retain prior
        // X-Forwarded-For information as a comma+space
        // separated list and fold multiple headers into one.
        if prior, ok := r.Header["X-Forwarded-For"]; ok {
            clientIP = strings.Join(prior, ", ") + ", " + clientIP
        }
        r.Header.Set("X-Forwarded-For", clientIP)
    }
}

// First delete the old headers and add the new ones
func copyRespHeaders(d, s http.Header) {
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

// Accept() new socket connections from the listener
// Note:
//   - HTTPProxy is also a TCPListener
//   - http.Server.Serve() is passed a Listener object (p)
//   - And, Serve() calls Accept() before starting service
//     go-routines
func (p *HTTPProxy) Accept() (net.Conn, error) {
    ln := p.TCPListener
    la := ln.Addr().String()
    for {
        ln.SetDeadline(time.Now().Add(2 * time.Second))

        nc, err := ln.Accept()

        select {
        case _ = <- p.stop:
            if err == nil {
                nc.Close()
            }
            return nil, &errShutdown

        default:
        }

        if err != nil {
            if ne, ok := err.(net.Error); ok {
                if ne.Timeout() || ne.Temporary() {
                    continue
                }
            }
            return nil, err
        }

        if p.rl.Limit() {
            p.log.Debug("%s: Ratelimited: %s", la, nc.RemoteAddr().String())
            nc.Close()
            continue
        }

        if !AclOK(p.conf, nc) {
            p.log.Debug("%s: ACL failure: %s", la, nc.RemoteAddr().String())
            nc.Close()
            continue
        }

        return nc, nil
    }
}



var (
    errShutdown = proxyErr{Err: "server shutdown", temp: false}

    // used when we hijack for CONNECT
    _200Ok []byte = []byte("HTTP/1.0 200 OK\r\n\r\n")
)

type proxyErr struct {
    error
    Err string
    temp bool       // is temporary error?
}

// net.Error interface implementation
func (e *proxyErr) String()    string  { return e.Err }
func (e *proxyErr) Temporary() bool { return e.temp }
func (e *proxyErr) Timeout()   bool { return false }


