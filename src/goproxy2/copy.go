// copy.go - cancellable copy on sockets
//
// Author: Sudhi Herle <sudhi@herle.net>
// License: GPLv2
//
// This software does not come with any express or implied
// warranty; it is provided "as is". No claim  is made to its
// suitability for any purpose.

package main

import (
        "io"
        "net"
        "context"
)

func CancellableCopy(ctx context.Context, d, s *net.TCPConn, b []byte) {
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

// vim: noexpandtab:ts=8:sw=8:
