// copy.go -- cancellable I/O copy
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
	"io"
	"sync"
	"time"
)


type CancellableCopier struct {
	Lhs *net.TCPConn
	Rhs *net.TCPConn

	ReadTimeout int
	WriteTimeout int

	IOBufsize  int
}

// CancellableCopy does bi-directional I/O between two connections d & s. It is cancellable
// if the context 'ctx' is cancelled.
// It returns number of bytes transferred in each direction.
func (c *CancellableCopier) Copy(ctx context.Context) (nLhs, nRhs int, err error) {

	bufsz := c.IOBufsize
	if bufsz <= 0 {
		bufsz = 16384
	}

	if c.ReadTimeout <= 0 {
		c.ReadTimeout = 10  // seconds
	}

	if c.WriteTimeout <= 0 {
		c.WriteTimeout = 15 // seconds
	}

	// have to wait until both go-routines are done.
	var wg sync.WaitGroup

	// this channel tells us when both go-routines have terminated.
	// It's a proxy for wg.Wait(); necessary since we will wait on
	// another channel (ctx.Done()) concurrently with this.
	ch := make(chan bool)

	wg.Add(2)
	go func() {
		wg.Wait()
		close(ch)
	}()

	b0 := make([]byte, bufsz)
	b1 := make([]byte, bufsz)

	// copy #1
	go func() {
		defer wg.Done()
		_, nLhs, _ = c.copyBuf(c.Lhs, c.Rhs, b0)
	}()

	// copy #2
	go func() {
		defer wg.Done()
		_, nRhs, _ = c.copyBuf(c.Rhs, c.Lhs, b1)
	}()


	// Wait for parent to kill us or the copy routines to end.
	// If parent kills us, we wait for copy-routines to end as well.
	select {
	case <-ctx.Done():
		// close the sockets and force the i/o loop in copybuf to end.
		c.Lhs.Close()
		c.Rhs.Close()
		<- ch

	case <-ch:
	}


	// XXX Gah which error do I report?
	err = nil
	return
}



func (c *CancellableCopier) copyBuf(d, s *net.TCPConn, b []byte) (nr, nw int, err error) {
	rto := time.Duration(c.ReadTimeout) * time.Second
	wto := time.Duration(c.WriteTimeout) * time.Second
	for {
		s.SetReadDeadline(time.Now().Add(rto))
		nr, err = s.Read(b)
		if err != nil && err != io.EOF && err != context.Canceled && !isReset(err) {
			return
		}
		if nr > 0 {
			d.SetWriteDeadline(time.Now().Add(wto))
			nw, err = d.Write(b[:nr])
			if err != nil {
				return
			}
			if nw != nr {
				return
			}
		}
		if err != nil || nr == 0 {
			return
		}
	}

	d.CloseWrite()
	s.CloseRead()
	err = nil
	return
}
