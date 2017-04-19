// proxy.go -- http proxy logic
package main

import (
    "io"
    "time"
    "context"
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
        // XXX We don't do this
        http.Error(w, "No support for CONNECT", 500)
        return
    }

    if !r.URL.IsAbs() {
        http.Error(w, "No support for non-proxy requests", 500)
        return
    }

    t0 := time.Now()

    scrubReq(r)

    resp, err := p.tr.RoundTrip(r)
    if err != nil {
        http.Error(w, err.Error(), 500)
        return
    }

    t1 := time.Now()

    copyHeaders(w.Header(), resp.Header)
    w.WriteHeader(resp.StatusCode)
    nr, _ := io.Copy(w, resp.Body)
    resp.Body.Close()

    t2 := time.Now()

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

