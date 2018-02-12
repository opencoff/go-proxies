// sockss.go - SOCKSv5 Proxy Server
//
// Author: Sudhi Herle <sudhi@herle.net>
// License: GPLv2
//
// This software does not come with any express or implied
// warranty; it is provided "as is". No claim  is made to its
// suitability for any purpose.

package socks5

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"net"
	"sync"
	"time"
	stdlog "log"
	"context"
	"errors"
	"syscall"
)

type Proxy struct {
	Dialer *net.Dialer

	// How frequently do we shove bytes forcibly down the pipe?
	FlushInterval time.Duration

	// if present, checks to see if remote connect should be allowed
	// default is to assume that the connection is allowed.
	AllowConnect func(client net.Addr, remote net.Addr) bool

	// event notifiers
	NotifyConnect func(client net.Addr, remote net.Addr)
	NotifyClose   func(client net.Addr, remote net.Addr)

	// Error log
	ErrorLog *stdlog.Logger

	// XXX Timeouts
}

// The incoming client and their credentials
type Client struct {
	AuthType []byte // 0: none, 1: GSSAPI, 2: username/passwd, rest: reserved

	User   string // username
	Passwd string // password

	Client net.Addr // client address
	Server net.Addr // server address
}


// Well known timeouts
type Timeouts struct {

	// timeout for receiving auth methods request
	AuthTimeout time.Duration

	// timeout for receiving connect request
	RequestTimeout time.Duration

	// body I/O deadlines
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
}

type Server struct {
	mu  sync.Mutex

	// internal objs that make up a server
	pr *Proxy

	to Timeouts

	listeners map[net.Listener]bool
	conns     map[*conn]bool

	// private fields
	done chan bool
}

// initialize server 's' to work with Proxy 'p'
func NewServer(p *Proxy, to *Timeouts) (*Server, error) {
	s := &Server{
		pr:        p,
		to:        *to,
		done:      make(chan bool),
		listeners: make(map[net.Listener]bool),
		conns:     make(map[*conn]bool),
	}

	if p.AllowConnect == nil {
		p.AllowConnect = func(a, b net.Addr) bool {
			return true
		}
	}

	if p.NotifyConnect == nil {
		p.NotifyConnect = func(a, b net.Addr) {}
	}

	if p.NotifyClose == nil {
		p.NotifyClose = func(a, b net.Addr) {}
	}

	return s, nil
}

// We only provide one.
func (s *Server) Serve(ln net.Listener) error {

	defer ln.Close()

	var errDelay time.Duration   = 2500 * time.Microsecond
	const maxDelay time.Duration = 1 * time.Second

	ctx := context.Background()
	ctx  = context.WithValue(ctx, "socks5-server", s)
	ctx, cancel := context.WithCancel(ctx)

	s.addListener(ln)
	defer s.rmListener(ln)

	for {
		nc, e := ln.Accept()
		if e == nil {
			errDelay = 2500 * time.Microsecond

			c := s.newConn(nc)

			go c.serve(ctx)
			continue
		}

		select {
		case <-s.done:
			cancel()
			return ErrServerClosed
		default:
		}

		// temporary failures, exponential backoff
		if ne, ok := e.(net.Error); ok && ne.Temporary() {
			errDelay *= 2
			if errDelay > maxDelay {
				errDelay = maxDelay
			}
			//s.log("socks5-server: temporary accept() error: %v; retrying in %v", e, errDelay)
			time.Sleep(errDelay)
			continue
		}

		// All other errors are sent back to caller
		return e
	}
}


// Gracefully shutdown the server
func (s *Server) Shutdown(ctx context.Context) error {
	// 1. close active listeners
	// 2. close done chan
	// 3. wait for active conns to be closed

	s.mu.Lock()
	s.rmListenersAndCloseLocked()
	close(s.done)
	s.closeActiveConnLocked()

	s.mu.Unlock()

	for {
		// XXX How long to wait for active conns to go away?
		// how will I know

		select {
		case <-ctx.Done():
			return ctx.Err()

			// XXX ??
		}
	}

}

func (s *Server) addListener(ln net.Listener) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.listeners[ln] = true
}

// Only untrack the given listener. don't close it! The caller
func (s *Server) rmListener(ln net.Listener) {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.listeners, ln)
}

// remove and close all listeners
func (s *Server) rmListenersAndCloseLocked() {
	for ln := range s.listeners {
		delete(s.listeners, ln)
		ln.Close()
	}
}


// close all active connections
func (s *Server) closeActiveConnLocked() {
	for c := range s.conns {
		delete(s.conns, c)
		c.close()
	}
}

func (s *Server) newConn(nc net.Conn) *conn {
	c := &conn{
		srv: s,
		c:   nc,
		car: nc.RemoteAddr(),
		cal: nc.LocalAddr(),
		buf: make([]byte, 0, 32768),
	}

	s.mu.Lock()
	s.conns[c] = true
	s.mu.Unlock()

	return c
}

type conn struct {
	srv *Server
	c   net.Conn
	r   net.Conn    // remote connection

	buf []byte      // I/O buffer for client to server (tcp)
	car net.Addr    // client addr remote
	cal net.Addr    // client add local; i.e., the server's listening addr
}

// started as a go-routine in Server:Serve()
func (c *conn) serve(ctx context.Context) {

	var b []byte

	// XXX do we catch/recover a panic from deep in the call chain
	//     below?

	defer c.close()


	rem  := c.car
	conn := c.c
	prox := c.srv.pr

	log := func(z string, v ...interface{}) {
		x := fmt.Sprintf("%s: %s", rem, z)
		prox.ErrorLog.Printf(x, v...)
	}

	// 1. Read version & auth supported methods
	b = c.buf[:1024]
	n, err := conn.Read(b)
	if err != nil {
		if err != io.EOF {
			log("can't read version info: %s", err)
		}
		return
	}

	if n < 2 {
		log("partial data while reading version; exp 2 saw %d", n)
		return
	}

	ver   := b[0]
	nmeth := int(b[1])
	n -= 2

	if ver != 5 {
		b = c.buf[:2]
		b[0] = 5
		b[1] = 0xff // unsupported version
		conn.Write(b)
		return
	}

	if n < nmeth {
		log("partial data while reading auth methods; exp %d saw %d", nmeth, n)
		return
	}

	b = c.buf[:2]
	b[0] = 5
	b[1] = 0    // no auth needed
	_, err = conn.Write(b)
	if err != nil {
		log("client write error: %s", err)
		return
	}

	// 2. Read URL/host to connect to
	b = c.buf[:512]
	n, err = conn.Read(b)
	if err != nil {
		log("can't read destination: %s", err)
		if err != io.EOF {
			//log("can't read destination: %s", err)
		}
		return
	}
	xn   := n

	badaddr := func(z byte) {
		b   := c.buf[:xn]
		b[1] = z    // bad address -- no other avail code?
		conn.Write(b)
	}

	// Packet Format:
	//
	//    0                   1                   2                   3
	//    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	//   | Version       |Command Code   |  RESERVED     | Addr Type     |
	//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	//   |  Address (Variable Length)                                    |
	//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	//   |  Address (Variable Length)                                    |
	//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	//   | Address (Variable Length)     | Port Number in Network Order  |
	//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

	if n < 10 {
		log("partial data while reading destination; exp %d saw %d", 10, n)
		return
	}

	if b[1] != 1 {
		badaddr(7)
		log("only TCP connect supported; saw %d", b[1])
	}

	var x bytes.Buffer
	var port uint

	n    -= 4
	atyp := b[3]
	b     = b[4:]
	switch atyp {
	case 0x1: // IPv4 Addr in MSB format
		if n < 4 {
			badaddr(0xff)
			log("partial data while reading IPv4; exp %d saw %d", 4, n)
			return
		}
		x.WriteString(fmt.Sprintf("%d.%d.%d.%d", b[0], b[1], b[2], b[3]))
		b = b[4:]

	case 0x3: // FQDN; first octet is length
		m := int(b[0])
		if n < m {
			badaddr(0xff)
			log("partial data while reading FQDN; exp %d saw %d", m, n)
			return
		}

		for i := 0; i < m; i++ {
			x.WriteString(fmt.Sprintf("%c", b[i+1]))
		}
		b = b[m+1:]

	case 0x4: // IPv6 addr in MSB format
		m := 16
		if n < m {
			badaddr(0xff)
			log("partial data while reading IPv6; exp %d saw %d", m, n)
			return
		}
		x.WriteString(fmt.Sprintf("[%02x", b[0]))
		for i := 1; i < m; i++ {
			x.WriteString(fmt.Sprintf(":%02x", b[i]))
		}
		x.WriteByte(']')
		b = b[16:]
	}

	port = uint(b[0]) << 8 + uint(b[1])
	x.WriteString(fmt.Sprintf(":%d", port))

	var saddr string = x.String()

	addr, err := net.ResolveTCPAddr("tcp", saddr)
	if err != nil {
		log("can't resolve %s: %s", saddr, err)
		badaddr(0xff)
		return
	}

	if ok := prox.AllowConnect(rem, addr); !ok {
		log("policy denial to %s", saddr)
		badaddr(0x05)	// conn refused
		return
	}

	rhs, err := prox.Dialer.DialContext(ctx, "tcp", saddr)
	if err != nil {
		log("can't connect to %s: %s", saddr, err)
		badaddr(0x3)
		return
	}
	defer rhs.Close()

	badaddr(0x0)	// all OK!

	prox.NotifyConnect(rem, addr)

	cpctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup

	wg.Add(2)

	go cancellableCopy(cpctx, rhs, conn, nil)
	go cancellableCopy(cpctx, conn, rhs, nil)

	// wait for both go-routines to end and then  close 'ch'
	cpdone := make(chan bool)
	go func(ch chan bool) {
		wg.Wait()
		close(ch)
		prox.NotifyClose(rem, addr)
	}(cpdone)

	// wait for go-routines to finish or we are asked to shutdown
	// When we cancel(), the go-routines return; which in turn causes
	// wg.Wait() to complete - and thus, cpdone to return zero.
	var done bool
	for !done {
		select {
		case <-c.srv.done:	// graceful shutdown
			cancel()

		case <-cpdone: // we are done copying
			done = true

		case <-ctx.Done(): // we were cancelled
			cancel()
		default:
		}
	}
}

func cancellableCopy(ctx context.Context, d, s net.Conn, b []byte) {
	if b == nil {
		b = make([]byte, 32768)
	}

	ch := make(chan error)
	go func() {
		ch <- copyBuf(d, s, b)
	}()

	select {
	case _ = <- ch:
		return
	case <- ctx.Done():
		s.Close()
		d.Close()
		<- ch
	}
}

func copyBuf(d, s net.Conn, b []byte) error {
	log := func(z string, v ...interface{}) {
		//x := fmt.Sprintf("%s->%s: %s\n", s.RemoteAddr().String(), d.RemoteAddr().String(), z)
		//stdlog.Printf(x, v...)
	}
	for {
		nr, err := s.Read(b[:cap(b)])
		if err != nil && err != io.EOF && err != context.Canceled && !isReset(err) {
			log("i/o error %s", err)
			return err
		}
		if nr > 0 {
			log("%d bytes read", nr)
			nw, werr := d.Write(b[:nr])
			if werr != nil {
				log("write error %s", werr)
				return werr
			}
			if nw != nr {
				log("partial write")
				return io.ErrShortWrite
			}
		}
		if err != nil {
			log("i/o error2 %s", err)
			return err
		}
	}

	return nil
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

func (c *conn) close() {
	c.c.Close()
	if c.r != nil {
		c.r.Close()
	}
}

var ErrServerClosed = errors.New("socks5: Server closed")

// vim: noexpandtab:sw=8:ts=8
