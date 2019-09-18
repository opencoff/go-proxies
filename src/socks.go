// sockss.go - SOCKSv5 Proxy Server
//
// Author: Sudhi Herle <sudhi@herle.net>
//
// This software does not come with any express or implied
// warranty; it is provided "as is". No claim  is made to its
// suitability for any purpose.

package main

import (
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
	"context"
	//"encoding/hex"

	L "github.com/opencoff/go-logger"
	"github.com/opencoff/go-ratelimit"
)

// SOCKSv5 methods
type Methods struct {
	ver, nmethods uint8
	methods       []uint8
}

// Socks Proxy config
// A listenr and its ACL
type socksProxy struct {
	*net.TCPListener

	cfg  *ListenConf // config block

	bind net.Addr    // address to bind to when connect to remote
	log  *L.Logger   // Shortcut to logger
	ulog *L.Logger   // URL Logger

	grl  *ratelimit.RateLimiter
	prl  *ratelimit.PerIPRateLimiter

	ctx  context.Context
	cancel context.CancelFunc

	wg   sync.WaitGroup
}

// Make a new proxy server
func NewSocksv5Proxy(cfg *ListenConf, log, ulog *L.Logger) (px *socksProxy, err error) {
	la, err := net.ResolveTCPAddr("tcp", cfg.Listen)
	if err != nil {
		die("Can't resolve %s: %s", cfg.Listen, err)
	}

	ln, err := net.ListenTCP("tcp", la)
	if err != nil {
		return nil, err
	}

	var addr net.Addr

	if len(cfg.Bind) > 0 {
		log.Info("Binding to %s ..\n", cfg.Bind)
		addr, err = net.ResolveTCPAddr("tcp", cfg.Bind)

		if err != nil {
			return nil, err
		}
	}

	log = log.New("socks-"+ln.Addr().String(), 0)

	grl, _ := ratelimit.New(cfg.Ratelimit.Global, 1)
	prl, _ := ratelimit.NewPerIP(cfg.Ratelimit.PerHost, 1, 30000)

	ctx, cancel := context.WithCancel(context.Background())
	px = &socksProxy{
		TCPListener:  ln,
		cfg:          cfg,
		bind:         addr,
		log:          log,
		ulog:         ulog,
		grl:          grl,
		prl:          prl,
		ctx:          ctx,
		cancel:       cancel,
	}

	return
}

func (px *socksProxy) Start() {
	px.wg.Add(1)
	go func() {
		defer px.wg.Done()
		px.log.Info("Starting SOCKS proxy ..")
		px.accept()
	}()
}

func (px *socksProxy) Stop() {
	px.cancel()
	px.TCPListener.Close()
	px.wg.Wait()

	px.log.Info("SOCKS proxy shutdown")
}


// start the proxy
// Caller is expected to kick this off as a go-routine
// XXX Also need a global limit on total concurrent connections?
func (px *socksProxy) accept() {
	ln := px.TCPListener
	log := px.log
	nerr := 0

	for {
		ln.SetDeadline(time.Now().Add(2 * time.Second))
		conn, err := ln.Accept()
		select {
		case <-px.ctx.Done():
			return
		default:
		}

		if err != nil {
			if ne, ok := err.(net.Error); ok {
				if ne.Timeout() || ne.Temporary() {
					continue
				}
			}

			log.Error("Failed to accept new connection: %s", err)
			nerr += 1
			if nerr > 5 {
				log.Error("Too many consecutive accept failures! Aborting...")
				die("Aborting gosocksd due to too many failures!")
			}
			continue
		}

		rem := conn.RemoteAddr().String()

		// Ratelimit before anything else we do
		if px.grl.Limit() {
			conn.Close()
			log.Debug("global ratelimit reached: %s", rem)
			continue
		}

		if px.prl.Limit(conn.RemoteAddr()) {
			conn.Close()
			log.Debug("per-host ratelimit reached: %s", rem)
			continue
		}

		// Reset - as soon as things begin to work
		nerr = 0

		// Check ACL
		if !AclOK(px.cfg, conn) {
			conn.Close()
			log.Debug("Denied %s due to ACL", rem)
			continue
		}

		log.Debug("Accepted connection from %s", rem)

		// Fork off a handler for this new connection
		px.wg.Add(1)
		go px.Proxy(conn)
	}
}

// goroutine to handle a proxy request from 'lhs'
func (px *socksProxy) Proxy(lhs net.Conn) {

	defer px.wg.Done()

	// We expect to get some bytes within 10 seconds.
	//lhs.SetReadDeadline(deadLine(10000))

	_, err := px.readMethods(lhs)

	if err != nil {
		return
	}

	// Hard coded response: "We have no need for auth"
	buf := make([]byte, 2)
	buf[0] = 5
	buf[1] = 0
	lhs.Write(buf)

	// Now we expect to read URL and connect
	rhs, s, err := px.doConnect(lhs)
	if err != nil {
		return
	}

	// Set read and write deadlines.
	// XXX In general any socket connection must complete its I/O within
	//     10 minutes.
	//
	/*
	   tout, _ := time.ParseDuration("3m")
	   //tout, _ := time.ParseDuration("10m")

	   dl := time.Now().Add(tout)
	   lhs.SetDeadline(dl)
	   rhs.SetDeadline(dl)
	*/

	lx := lhs.(*net.TCPConn)
	rx := rhs.(*net.TCPConn)

	cp := &CancellableCopier{
		Lhs:          lx,
		Rhs:          rx,
		ReadTimeout:  10,	// XXX Config file
		WriteTimeout: 15,	// XXX Config file
		IOBufsize:    16384,
	}

	cp.Copy(px.ctx)

	if px.ulog != nil {
		now := time.Now().UTC()
		yy, mm, dd := now.Date()
		hh, m, ss := now.Clock()
		us := int(now.Nanosecond() / 1e3)

		ls := lx.RemoteAddr().String()
		rs := rx.RemoteAddr().String()
		s := fmt.Sprintf("%s %04d-%02d-%02d %02d:%02d:%02d.%06d %s [%s]",
			ls, yy, mm, dd, hh, m, ss, us, s, rs)

		px.ulog.Info(s)
	}
}

// Read the advertised methods from the client and respond
func (px *socksProxy) readMethods(conn net.Conn) (m Methods, err error) {
	rem := conn.RemoteAddr().String()
	b := make([]byte, 300)
	n, err := conn.Read(b)
	if err != nil && err != io.EOF {
		px.log.Error("%s Unable to read version info: %s", rem, err)
		return
	}

	if n < 2 {
		errs := fmt.Sprintf("%s Insufficient data while reading version: Saw only %d bytes\n",
			rem, n)
		px.log.Error(errs)
		err = errors.New(errs)
		return
	}

	m.ver = b[0]
	m.nmethods = b[1]

	if n-2 < int(m.nmethods) {
		errs := fmt.Sprintf("%s insufficient data while reading methods; exp %d bytes, saw %d",
			rem, m.nmethods, n-2)
		px.log.Error(errs)
		err = fmt.Errorf(errs)
	}

	//px.log.Debug("%s Methods: %d bytes [%d tot auth meth]\n%s\n", rem, n, int(m.nmethods),
	//            hex.Dump(b[0:n]))

	m.methods = b[2 : 2+int(m.nmethods)]

	return
}

// Read the connect request and return a successful connection to
// the other side
func (px *socksProxy) doConnect(lhs net.Conn) (rhs net.Conn, s string, err error) {
	ls := lhs.RemoteAddr().String()

	buf := make([]byte, 512)
	log := px.log

	n, err := lhs.Read(buf)
	if err != nil {
		if err != io.EOF {
			log.Error("%s Unable to read version info: %s", ls, err)
		}
		return
	}

	//log.Debug("%s Connect: %d bytes\n%s\n", ls, n, hex.Dump(buf[0:n]))

	// Packet Format:
	// field 1: [0] Version# (must be 0x5)
	// field 2: [1] command code:
	//          0x1: TCP Conn
	//          0x2: TCP Port
	//          0x3: UDP Conn
	// field 3: [2] 0x0 (reserved)
	// field 4: [3] addr type:
	//          0x1: IPv4 (MSB)
	//          0x3: FQDN
	//          0x4: IPv6
	// field 5: dest address: one of:
	//          - 4 bytes of IPv4 address
	//          - 16 bytes of IPv6 address
	//          - 1 byte len + N bytes of domain name
	// field 6: [2] port number in network byte order
	//

	if n < 7 {
		errs := fmt.Sprintf("%s Insufficient data while reading connect: Saw %d, want 7\n",
			ls, n)
		log.Error(errs)
		err = errors.New(errs)
		return
	}

	var t string
	var i int

	switch buf[3] {
	case 0x1:
		if n-4 < 4 {
			errs := fmt.Sprintf("%s Insufficient data for IPv4 addr: saw %d, want 4\n",
				ls, n-4)
			log.Error(errs)
			err = errors.New(errs)
			return
		}
		s += fmt.Sprintf("%d", buf[4])
		s += fmt.Sprintf(".%d", buf[5])
		s += fmt.Sprintf(".%d", buf[6])
		s += fmt.Sprintf(".%d", buf[7])

	case 0x3:
		m := int(buf[4])
		if n-4 < m {
			errs := fmt.Sprintf("%s Insufficient data for domain: saw %d, want %d\n",
				ls, n-4, m)
			log.Error(errs)
			err = errors.New(errs)
			return
		}

		for i = 0; i < m; i++ {
			s += fmt.Sprintf("%c", buf[i+5])
		}

	case 0x4:
		m := 16
		if n-4 < m {
			errs := fmt.Sprintf("%s Insufficient data for IPv6 addr: saw %d, want 16\n",
				ls, n-4)
			log.Error(errs)
			err = errors.New(errs)
			return
		}
		s = fmt.Sprintf("[%02x", buf[5])
		for i = 1; i < m; i++ {
			s += fmt.Sprintf(":%02x", buf[i+5])
		}
		s += "]"
	}

	var port uint16 = uint16(buf[n-2])<<8 + uint16(buf[n-1])

	s += fmt.Sprintf(":%d", port)

	switch buf[1] {
	case 1:
		t = "tcp"
	case 2: // bind
	case 3:
		t = "udp"
	}

	//log.Debug("Connecting to %s ..\n", s)

	/*
	   tout := time.Duration(px.cfg.Conn_tout) * time.Second
	   if tout <= 0 {
	       tout, _ = time.ParseDuration("4s")
	   }
	*/
	d := &net.Dialer{LocalAddr: px.bind, Timeout: 5 * time.Second}

	rhs, err = d.Dial(t, s)
	if err != nil {
		log.Error("%s failed to connect to %s: %s", ls, s, err)
		buf[1] = 4
		lhs.Write(buf[:n])
		return
	}

	buf[1] = 0
	lhs.Write(buf[:n])

	log.Debug("%s connected to %s [%s]", ls, s, rhs.RemoteAddr().String())

	//log.Info("%s CONNECT %s %s\n", ls, s, rhs.RemoteAddr().String())

	return rhs, s, nil
}

// vim: ft=go:sw=8:ts=8:noexpandtab:tw=98:
