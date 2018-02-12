// proxy.go -- http proxy server logic
//
// Author: Sudhi Herle <sudhi@herle.net>
// License: GPLv2
//
// This software does not come with any express or implied
// warranty; it is provided "as is". No claim  is made to its
// suitability for any purpose.

package main

import (
	//"io"
	"fmt"
	"context"
	"net"
	"sync"
	"time"
	"strings"
	//"net/url"
	"net/http"

	"lib/httproxy"

	L "github.com/opencoff/go-lib/logger"
	"github.com/opencoff/go-lib/ratelimit"
)

// XXX These should be in a config file
const dialerTimeout       = 30    // seconds
const dialerKeepAlive     = 30    // seconds
const tlsHandshakeTimeout = 30    // seconds
const readTimeout         = 20    // seconds
const readHeaderTimeout   = 10    // seconds
const writeTimeout        = 60    // seconds; 3x read timeout. Enough time?
const flushInterval       = 10    // seconds
const perHostIdleConn     = 1024  // XXX too big?
const idleConnTimeout     = 120   // seconds
const defaultIOSize       = 8192  // bytes

type HTTPProxy struct {
	*net.TCPListener

	// listen address
	conf *ListenConf

	stop chan bool
	wg   sync.WaitGroup

	grl *ratelimit.Ratelimiter
	prl *ratelimit.PerIPRatelimiter

	// logger
	log  *L.Logger
	ulog *L.Logger

	dialer *net.Dialer
	tr *http.Transport
	srv *http.Server
	rp  *httproxy.Proxy
}

func NewHTTPProxy(lc *ListenConf, log, ulog *L.Logger) (Proxy, error) {
	var err error

	ln     := lc.Listen.TCPAddr
	log     = log.New(ln.String(), 0)
	stdlog := log.StdLogger()
	addr   := lc.Listen.TCPAddr

	p := &HTTPProxy{
		conf:        lc,
		log:         log,
		ulog:        ulog,
		stop:        make(chan bool),
	}

	p.grl, err = ratelimit.New(lc.Ratelimit.Global, 1)
	if err != nil {
		die("%s: Can't create global ratelimiter: %s", addr, err)
	}

	p.prl, err = ratelimit.NewPerIPRatelimiter(lc.Ratelimit.PerHost, 1)
	if err != nil {
		die("%s: Can't create per-host ratelimiter: %s", addr, err)
	}

	p.dialer = &net.Dialer{
		Timeout:   dialerTimeout * time.Second,
		KeepAlive: dialerKeepAlive * time.Second,
	}
	if lc.Bind.TCPAddr != nil {
		p.dialer.LocalAddr = lc.Bind.TCPAddr
	}

	p.tr = &http.Transport{
		Dial:                p.dialer.Dial,
		TLSHandshakeTimeout: tlsHandshakeTimeout * time.Second,
		MaxIdleConnsPerHost: perHostIdleConn,
		IdleConnTimeout:     idleConnTimeout * time.Second,
		DisableCompression:  true,
	}


	p.rp = &httproxy.Proxy{
		Transport:     p.tr,
		FlushInterval: flushInterval * time.Second,
		ErrorLog:      stdlog,
		BufferPool:    newBufPool(defaultIOSize),
		Director:      p.proxyURL,
	}

	p.srv = &http.Server{
		Addr:              addr.String(),
		Handler:           p,
		ReadTimeout:       readTimeout * time.Second,
		ReadHeaderTimeout: readHeaderTimeout * time.Second,
		WriteTimeout:      writeTimeout * time.Second,
		MaxHeaderBytes:    1 << 20,
		ErrorLog:          stdlog,
		ConnState:         func(c net.Conn, s http.ConnState) {
			switch s {
			case http.StateNew:
				// ++OpenConn
			case http.StateHijacked:
				// --OpenConn
			case http.StateClosed:
				// --OpenConn
			}
		},
	}

	return p, nil
}

func (p *HTTPProxy) Start() {
	ln, err := net.ListenTCP("tcp", p.conf.Listen.TCPAddr)
	if err != nil {
		die("Can't listen on %s: %s", p.conf.Listen.String(), err)
	}

	p.TCPListener = ln
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()

		lc := p.conf

		p.log.Info("Starting http-proxy ..")
		p.log.Info("Ratelimit: Global %d req/s, Per-host: %d req/s",
			lc.Ratelimit.Global, lc.Ratelimit.PerHost)

		p.srv.Serve(p)
	}()
}

func (p *HTTPProxy) Stop() {
	close(p.stop)

	cx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	p.srv.Shutdown(cx)

	defer cancel()

	p.wg.Wait()
	p.log.Info("http-proxy shutdown")
}


func (p *HTTPProxy) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	// XXX Add a health-check URL?
	if upg := headerGet(req.Header, "Upgrade"); strings.ToLower(upg) == "websocket" {
		err := p.serveWebSocket(rw, req)
		if err != nil {
			p.log.Warn("can't serve websocket: %s", err)
			http.Error(rw, "can't serve websocket", http.StatusBadGateway)
		}
		return
	}

	p.rp.ServeHTTP(rw, req)
}


func (p *HTTPProxy) serveWebSocket(rw http.ResponseWriter, req *http.Request) error {
	req.URL.Host = req.Host

	ctx := req.Context()
	dconn, err := p.dialer.DialContext(ctx, "tcp", req.Host)
	if err != nil {
		return fmt.Errorf("can't dial websocket to %s: %v", req.Host, err)
	}
	defer dconn.Close()

	hj, ok := rw.(http.Hijacker)
	if !ok {
		return fmt.Errorf("not a hijacker")
	}

	cconn, buf, err := hj.Hijack()
	if err != nil {
		return fmt.Errorf("can't hijack: %v", err)
	}
	defer cconn.Close()

	if clientIP, _, err := net.SplitHostPort(req.RemoteAddr); err == nil {
		if prior, ok := req.Header["X-Forwarded-For"]; ok {
			clientIP = strings.Join(prior, ", ") + ", " + clientIP
		}
		req.Header.Set("X-Forwarded-For", clientIP)
	}

	err = req.Write(dconn)
	if err != nil {
		return err
	}

	nctx, cancel := context.WithCancel(ctx)

	buf.WriteTo(dconn)
	b0 := p.rp.BufferPool.Get()
	b1 := p.rp.BufferPool.Get()

	defer p.rp.BufferPool.Put(b0)
	defer p.rp.BufferPool.Put(b1)

	var wg sync.WaitGroup
	wg.Add(2)

	d := dconn.(*net.TCPConn)
	s := cconn.(*net.TCPConn)

	go func() {
		defer wg.Done()
		CancellableCopy(nctx, d, s, b0)
	}()

	go func() {
		defer wg.Done()
		CancellableCopy(nctx, s, d, b1)
	}()

	select {
	case <-p.stop:
		cancel()
	case <-ctx.Done():
		cancel()
	}

	wg.Wait()
	return nil
}


// Notes:
//	 - HTTPProxy is also a TCPListener
//	 - http.Server.Serve() is passed a Listener object (p)
//	 - And, Serve() calls Accept() before starting service
//	 - Serve() eventually calls our ServeHTTP() above.
func (p *HTTPProxy) Accept() (net.Conn, error) {
	ln := p.TCPListener
	for {
		ln.SetDeadline(time.Now().Add(2 * time.Second))

		nc, err := ln.Accept()

		select {
		case _ = <-p.stop:
			if err == nil {
				nc.Close()
			}
			return nil, errShutdown

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

		// First enforce a global ratelimit
		if p.grl.Limit() {
			p.log.Debug("global ratelimit reached: %s", nc.RemoteAddr().String())
			nc.Close()
			continue
		}

		// Then a per-host ratelimit
		if p.prl.Limit(nc.RemoteAddr()) {
			p.log.Debug("per-host ratelimit reached: %s", nc.RemoteAddr().String())
			nc.Close()
			continue
		}

		if !AclOK(p.conf, nc) {
			p.log.Debug("ACL failure: %s", nc.RemoteAddr().String())
			nc.Close()
			continue
		}

		return nc, nil
	}
}

// Authentication and req modification callback from the proxy core
func (p *HTTPProxy) proxyURL(r *http.Request) (int, error) {

	// golang parses the requestURI and populates:
	// - r.RequestURI
	// - r.Host: This is either the host in the URL or the HTTP Header.
	// - r.URL.Path
	// - r.URL.RawQuery

	// Dialer needs a valid URL.Host;
	r.URL.Host = r.Host

	return http.StatusOK, nil
}


func headerGet(h http.Header, k string) string {
	if v, ok := h[k]; ok {
		if len(v) > 0 {
			return v[0]
		}
	}
	return ""
}

// vim: noexpandtab:sw=8:ts=8:
