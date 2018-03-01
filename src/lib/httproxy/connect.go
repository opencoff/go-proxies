// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Changes (c) 2018 - Sudhi Herle
// - Teach it to authenticate/verify/transform requests before
//	 proxying
// - add support for CONNECT method

// HTTP proxy handler
package httproxy

import (
	"io"
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"syscall"
)


// CONNECT support
func (p *Proxy) doConnect(w http.ResponseWriter, r *http.Request) {
	h, ok := w.(http.Hijacker)
	if !ok {
		p.logf("can't do CONNECT: hijack failed")
		http.Error(w, "Can't support CONNECT", 501)
		return
	}

	client, _, err := h.Hijack()
	if err != nil {
		// Likely HTTP/2.x -- its OK
		p.logf("can't do CONNECT: hijack failed: %s", err)
		http.Error(w, "Can't support CONNECT", 501)
		client.Close()
		return
	}
	defer client.Close()

	host := r.URL.Host
	if i := strings.LastIndex(host, ":"); i < 0 {
		host += ":80"
	}

	ctx := r.Context()
	dest, err := p.Transport.DialContext(ctx, "tcp", host)
	if err != nil {
		p.logf("can't connect to %s: %s", host, err)
		http.Error(w, fmt.Sprintf("can't connect to %s", host), 500)
		client.Close()
		return
	}
	defer dest.Close()


	s := client.(*net.TCPConn)
	d := dest.(*net.TCPConn)

	s.Write(_200Ok)

	//p.logf("%s: CONNECT %s", s.RemoteAddr().String(), host)

	var b0, b1 []byte
	if p.BufferPool != nil {
		b0 = p.BufferPool.Get()
		b1 = p.BufferPool.Get()
	}

	nctx, cancel := context.WithCancel(ctx)

	// have to wait until both go-routines are done.
	var wg sync.WaitGroup

	wg.Add(2)
	go func() {
		defer wg.Done()
		cancellableCopy(nctx, s, d, b0)
	}()

	go func() {
		defer wg.Done()
		cancellableCopy(nctx, d, s, b1)
	}()

	done := false
	for !done {
		select {
		case <-ctx.Done():
			cancel()
			done = true
		}
	}

	wg.Wait()

	if p.BufferPool != nil {
		p.BufferPool.Put(b0)
		p.BufferPool.Put(b1)
	}
}


func cancellableCopy(ctx context.Context, d, s *net.TCPConn, b []byte) {
	ch := make(chan error)
	go func() {
		ch <- copyBuf(d, s, b)
	}()

	select {
	case _ = <- ch:
		return
	case <- ctx.Done():
		s.CloseRead()
		d.CloseWrite()
		<- ch
	}
}

func copyBuf(d, s *net.TCPConn, b []byte) error {
	for {
		nr, err := s.Read(b)
		if err != nil && err != io.EOF && err != context.Canceled && !isReset(err) {
			return err
		}
		if nr > 0 {
			nw, err := d.Write(b[:nr])
			if err != nil {
				return err
			}
			if nw != nr {
				return io.ErrShortWrite
			}
		}
		if err != nil {
			return err
		}
	}

	d.CloseWrite()
	s.CloseRead()
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

var _200Ok []byte = []byte("HTTP/1.1 200 OK\r\n\r\n")

// vim: noexpandtab:ts=4:sw=4:
