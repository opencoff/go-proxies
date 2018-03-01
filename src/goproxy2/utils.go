// utils.go - misc utilities used by HTTP and Socks proxies
//
// Author: Sudhi Herle <sudhi@herle.net>
// License: GPLv2
//
// This software does not come with any express or implied
// warranty; it is provided "as is". No claim  is made to its
// suitability for any purpose.

package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"syscall"
	"time"

	"lib/httproxy"
)

var errShutdown = errors.New("server shutdown")

// Return true if the err represents a TCP PIPE or RESET error
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

// Format a time duration
func format(t time.Duration) string {
	u0 := t.Nanoseconds() / 1000
	ma, mf := u0/1000, u0%1000

	if ma == 0 {
		return fmt.Sprintf("%3.3d us", mf)
	}

	return fmt.Sprintf("%d.%3.3d ms", ma, mf)
}

// must listen on 'addr'; die on failure
func mustListen(addr string) *net.TCPListener {
	la, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		die("Can't resolve %s: %s", addr, err)
	}

	ln, err := net.ListenTCP("tcp", la)
	if err != nil {
		die("Can't listen on %s: %s", addr, err)
	}

	return ln
}

// Return true if the new connection 'conn' passes the ACL checks
// Return false otherwise
func AclOK(cfg *ListenConf, conn net.Conn) bool {
	h, ok := conn.RemoteAddr().(*net.TCPAddr)
	if !ok {
		//p.log.Debug("%s can't extract TCP Addr", conn.RemoteAddr().String())
		return false
	}

	for _, n := range cfg.Deny {
		if n.Contains(h.IP) {
			return false
		}
	}

	if len(cfg.Allow) == 0 {
		return true
	}

	for _, n := range cfg.Allow {
		if n.Contains(h.IP) {
			return true
		}
	}

	return false
}

// simple buffer pool
type bufPool struct {
	p sync.Pool
}

func newBufPool(siz int) httproxy.BufferPool {
	b := &bufPool{
		p: sync.Pool{
			New: func() interface{} {
				return make([]byte, siz)
			},
		},
	}
	return b
}

func (b *bufPool) Get() []byte {
	buf := b.p.Get().([]byte)
	if buf == nil {
		buf = make([]byte, 8192)
	}
	return buf
}

func (b *bufPool) Put(z []byte) {
	b.p.Put(z)
}

// vim: ft=go:sw=8:ts=8:noexpandtab:tw=98:
