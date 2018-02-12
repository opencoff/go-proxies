// socksplain.go -- plain socksv5 support
//
// Author: Sudhi Herle <sudhi@herle.net>
//
// This software does not come with any express or implied
// warranty; it is provided "as is". No claim  is made to its
// suitability for any purpose.

package main

import (
	"context"
	"net"
	"sync"
	"time"

	"lib/socks5"

	L "github.com/opencoff/go-lib/logger"
	"github.com/opencoff/go-lib/ratelimit"
)


type SocksProxy struct {
	*net.TCPListener

	// listen address
	conf *ListenConf

	stop chan bool
	wg	 sync.WaitGroup

	grl *ratelimit.Ratelimiter
	prl *ratelimit.PerIPRatelimiter

	srv *socks5.Server

	// logger
	log  *L.Logger
	ulog *L.Logger

}

func NewSocksProxy(lc *ListenConf, log, ulog *L.Logger) (Proxy, error) {
	var err error

	ln     := lc.Listen.TCPAddr
	log     = log.New(ln.String(), 0)
	stdlog := log.StdLogger()
	addr   := lc.Listen

	p := &SocksProxy{
		conf: lc,
		log: log,
		ulog: ulog,
		stop: make(chan bool),
	}

	// Conf file specifies ratelimit as N conns/sec
	p.grl, err = ratelimit.New(lc.Ratelimit.Global, 1)
	if err != nil {
		die("%s: Can't create global ratelimiter: %s", addr, err)
	}

	p.prl, err = ratelimit.NewPerIPRatelimiter(lc.Ratelimit.PerHost, 1)
	if err != nil {
		die("%s: Can't create per-host ratelimiter: %s", addr, err)
	}

	dialer := &net.Dialer{
		Timeout:   dialerTimeout * time.Second,
		KeepAlive: dialerKeepAlive * time.Second,
	}
	if lc.Bind.TCPAddr != nil {
		dialer.LocalAddr = lc.Bind.TCPAddr
	}


	prox := &socks5.Proxy{
		Dialer:        dialer,
		FlushInterval: 30 * time.Second,
		ErrorLog:      stdlog,
		NotifyConnect: p.notifyConnect,
		NotifyClose:   p.notifyClose,
	}

	tout := &socks5.Timeouts{
		AuthTimeout:    5 * time.Second,
		RequestTimeout: 5 * time.Second,
		ReadTimeout:    30 * time.Second,
		WriteTimeout:   30 * time.Second,
	}

	p.srv, err = socks5.NewServer(prox, tout)
	if err != nil {
		die("Can't create socks5 server: %s", err)
	}

	return p, nil
}

// Start listener
func (p *SocksProxy) Start() {

	lc := p.conf
	ln, err := net.ListenTCP("tcp", lc.Listen.TCPAddr)
	if err != nil {
		die("Can't listen on %s: %s", lc.Listen.String(), err)
	}

	p.TCPListener = ln

	p.wg.Add(1)
	go func() {
		defer p.wg.Done()


		p.log.Info("Starting socksproxy ..")
		p.log.Info("Ratelimit: Global %d req/s, Per-host: %d req/s",
			lc.Ratelimit.Global, lc.Ratelimit.PerHost)

		err = p.srv.Serve(p)
		if err != nil {
			p.log.Error("socks server exited with %s", err)
		}
	}()
}

// Stop server
func (p *SocksProxy) Stop() {
	close(p.stop)

	cx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	p.srv.Shutdown(cx)

	defer cancel()

	p.wg.Wait()
	p.log.Info("authproxy shutdown")
}

// Accept() new socket connections from the listener
// Note:
//	 - SocksProxy is also a TCPListener
//	 - http.Server.Serve() is passed a Listener object (p)
//	 - And, Serve() calls Accept() before starting service
//	   go-routines
func (p *SocksProxy) Accept() (net.Conn, error) {
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

		p.log.Debug("accepted new client %s", nc.RemoteAddr().String())
		return nc, nil
	}
}


func (p *SocksProxy) notifyConnect(a, b net.Addr) {
	if p.ulog != nil {
		p.ulog.Info("socks5: connect %s -- %s", a.String(), b.String())
	}

	p.log.Debug("socks5: connect %s %s", a.String(), b.String())
}

func (p *SocksProxy) notifyClose(a, b net.Addr) {
	if p.ulog != nil {
		p.ulog.Info("socks5: disconnect %s -- %s", a.String(), b.String())
	}

	p.log.Debug("socks5: disconnect %s %s", a.String(), b.String())
}

// vim: noexpandtab:ts=8:sw=8:
