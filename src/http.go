// proxy.go -- http proxy logic
//
// Author: Sudhi Herle <sudhi@herle.net>
//
// This software does not come with any express or implied
// warranty; it is provided "as is". No claim  is made to its
// suitability for any purpose.

package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	L "github.com/opencoff/go-logger"
	"github.com/opencoff/go-ratelimit"
)

type HTTPProxy struct {
	*net.TCPListener

	// listen address
	conf *ListenConf

	grl *ratelimit.RateLimiter
	prl *ratelimit.PerIPRateLimiter

	log  *L.Logger
	ulog *L.Logger

	ctx    context.Context
	cancel context.CancelFunc

	tr *http.Transport

	srv *http.Server

	wg sync.WaitGroup
}

func NewHTTPProxy(lc *ListenConf, log, ulog *L.Logger) (Proxy, error) {
	addr := lc.Listen
	la, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		die("Can't resolve %s: %s", addr, err)
	}

	ln, err := net.ListenTCP("tcp", la)
	if err != nil {
		die("Can't listen on %s: %s", addr, err)
	}

	// Conf file specifies ratelimit as N conns/sec
	grl, _ := ratelimit.New(lc.Ratelimit.Global, 1)
	prl, _ := ratelimit.NewPerIP(lc.Ratelimit.PerHost, 1, 30000)

	ctx, cancel := context.WithCancel(context.Background())

	d := &net.Dialer{
		Timeout:   5 * time.Second,
		KeepAlive: 10 * time.Second,
	}

	p := &HTTPProxy{
		TCPListener: ln,
		conf:        lc,
		log:         log.New("http-"+ln.Addr().String(), 0),
		ulog:        ulog,
		grl:         grl,
		prl:         prl,
		ctx:         ctx,
		cancel:      cancel,

		tr: &http.Transport{
			Dial:                d.Dial,
			TLSHandshakeTimeout: 8 * time.Second,
			MaxIdleConnsPerHost: 32,
			IdleConnTimeout:     60 * time.Second,
		},

		srv: &http.Server{
			Addr:           addr,
			ReadTimeout:    5 * time.Second,
			WriteTimeout:   10 * time.Second,
			MaxHeaderBytes: 1 << 20,
		},
	}

	p.srv.Handler = p

	return p, nil
}

// Start listener
func (p *HTTPProxy) Start() {

	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		p.log.Info("Starting HTTP proxy ..")
		p.srv.Serve(p)
	}()
}

// Stop server
// XXX Hijacked Websocket conns are not shutdown here
func (p *HTTPProxy) Stop() {
	p.cancel()
	p.TCPListener.Close() // causes Accept() to abort

	cx, cancel := context.WithTimeout(p.ctx, 10*time.Second)
	p.srv.Shutdown(cx)
	cancel()

	p.wg.Wait()
	p.log.Info("HTTP proxy shutdown")
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

	ctx := r.Context()

	req := r.WithContext(ctx) // includes shallow copy of maps etc.
	if r.ContentLength == 0 {
		req.Body = nil
	}

	req.Header = cloneCleanHeader(r.Header)
	req.Close = false

	/* XXX use config file to determine if we want to set XFF
	if clientIP, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		// If we aren't the first proxy retain prior
		// X-Forwarded-For information as a comma+space
		// separated list and fold multiple headers into one.
		if prior, ok := req.Header["X-Forwarded-For"]; ok {
			clientIP = strings.Join(prior, ", ") + ", " + clientIP
		}
		req.Header.Set("X-Forwarded-For", clientIP)
	}
	*/

	res, err := p.tr.RoundTrip(r)
	if err != nil {
		p.log.Debug("%s: %s", r.Host, err)
		http.Error(w, err.Error(), 500)
		return
	}

	t1 := time.Now()

	copyHeader(w.Header(), res.Header)

	// The "Trailer" header isn't included in the Transport's response,
	// at least for *http.Transport. Build it up from Trailer.
	announcedTrailers := len(res.Trailer)
	if announcedTrailers > 0 {
		trailerKeys := make([]string, 0, len(res.Trailer))
		for k := range res.Trailer {
			trailerKeys = append(trailerKeys, k)
		}
		w.Header().Add("Trailer", strings.Join(trailerKeys, ", "))
	}

	w.WriteHeader(res.StatusCode)
	if len(res.Trailer) > 0 {
		// Force chunking if we saw a response trailer.
		// This prevents net/http from calculating the length for short
		// bodies and adding a Content-Length.
		if fl, ok := w.(http.Flusher); ok {
			fl.Flush()
		}
	}

	nr, _ := io.Copy(w, res.Body)
	res.Body.Close() // close now, instead of defer, to populate res.Trailer

	if len(res.Trailer) == announcedTrailers {
		copyHeader(w.Header(), res.Trailer)
	} else {
		for k, vv := range res.Trailer {
			k = http.TrailerPrefix + k
			for _, v := range vv {
				w.Header().Add(k, v)
			}
		}
	}

	t2 := time.Now()

	p.log.Debug("%s: %d %d %s %s\n", r.Host, res.StatusCode, nr, t2.Sub(t0), r.URL.String())
	// Timing log
	if p.ulog != nil {
		d0 := format(t1.Sub(t0))
		d1 := format(t2.Sub(t1))

		now := time.Now().UTC().Format(time.RFC3339)

		p.ulog.Info("time=%q url=%q status=\"%d\" bytes=\"%d\" upstream=%q downstream=%q",
			now, r.URL.String(), res.StatusCode, nr, d0, d1)
	}
}

func extractHost(u *url.URL) string {
	h := u.Host

	i := strings.LastIndex(h, ":")
	if i < 0 {
		h += ":80"
	}
	return h
}

// handle HTTP CONNECT
func (p *HTTPProxy) handleConnect(w http.ResponseWriter, r *http.Request) {

	h, ok := w.(http.Hijacker)
	if !ok {
		p.log.Warn("can't do CONNECT: hijack failed")
		http.Error(w, "Can't support CONNECT", http.StatusNotImplemented)
		return
	}

	client, _, err := h.Hijack()
	if err != nil {
		// Likely HTTP/2.x -- its OK
		p.log.Warn("can't do CONNECT: hijack failed: %s", err)
		http.Error(w, "Can't support CONNECT", http.StatusNotImplemented)
		client.Close()
		return
	}

	host := extractHost(r.URL)


	ctx := r.Context()

	dest, err := p.tr.DialContext(ctx, "tcp", host)
	if err != nil {
		p.log.Debug("can't connect to %s: %s", host, err)
		http.Error(w, fmt.Sprintf("can't connect to %s", host), http.StatusInternalServerError)
		client.Close()
		return
	}

	client.Write(_200Ok)

	s := client.(*net.TCPConn)
	d := dest.(*net.TCPConn)

	p.log.Debug("%s: CONNECT %s", s.RemoteAddr().String(), host)


	cp := &CancellableCopier{
		Lhs:          s,
		Rhs:          d,
		ReadTimeout:  10,	// XXX Config file
		WriteTimeout: 15,	// XXX Config file
		IOBufsize:    16384,
	}

	cp.Copy(ctx)
}


// Accept() new socket connections from the listener
// Note:
//   - HTTPProxy is also a TCPListener
//   - http.Server.Serve() is passed a Listener object (p)
//   - And, Serve() calls Accept() before starting service
//     go-routines
func (p *HTTPProxy) Accept() (net.Conn, error) {
	ln := p.TCPListener
	for {
		nc, err := ln.Accept()
		select {
		case <-p.ctx.Done():
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

		if p.grl.Limit() {
			nc.Close()
			p.log.Debug("%s: globally ratelimited", nc.RemoteAddr().String())
			continue
		}

		if p.prl.Limit(nc.RemoteAddr()) {
			nc.Close()
			p.log.Debug("%s: per-IP ratelimited", nc.RemoteAddr().String())
			continue
		}

		if !AclOK(p.conf, nc) {
			p.log.Debug("%s: ACL failure", nc.RemoteAddr().String())
			nc.Close()
			continue
		}

		return nc, nil
	}
}

func cloneCleanHeader(h http.Header) http.Header {
	x := cloneHeader(h)
	return cleanHeaders(x)
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

func cloneHeader(h http.Header) http.Header {
	h2 := make(http.Header, len(h))
	for k, vv := range h {
		vv2 := make([]string, len(vv))
		copy(vv2, vv)
		h2[k] = vv2
	}
	return h2
}

// Hop-by-hop headers. These are removed when sent to the backend.
// http://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html
var hopHeaders = []string{
	"Connection",
	"Proxy-Connection", // non-standard but still sent by libcurl and rejected by e.g. google
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",      // canonicalized version of "TE"
	"Trailer", // not Trailers per URL above; http://www.rfc-editor.org/errata_search.php?eid=4522
	"Transfer-Encoding",
	"Upgrade",
}

func cleanHeaders(hdr http.Header) http.Header {
	if c := hdr.Get("Connection"); c != "" {
		for _, f := range strings.Split(c, ",") {
			if f = strings.TrimSpace(f); f != "" {
				hdr.Del(f)
			}
		}
	}

	for _, h := range hopHeaders {
		hdr.Del(h)
	}

	return hdr
}

var (
	errShutdown = proxyErr{Err: "server shutdown", temp: false}

	// used when we hijack for CONNECT
	_200Ok []byte = []byte("HTTP/1.0 200 OK\r\n\r\n")
)

type proxyErr struct {
	error
	Err  string
	temp bool // is temporary error?
}

// net.Error interface implementation
func (e *proxyErr) String() string  { return e.Err }
func (e *proxyErr) Temporary() bool { return e.temp }
func (e *proxyErr) Timeout() bool   { return false }

// vim: ft=go:sw=8:ts=8:noexpandtab:tw=98:
