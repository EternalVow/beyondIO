// Copyright (c) 2019 The Gnet Authors. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd
// +build darwin dragonfly freebsd linux netbsd openbsd

package beyondIO

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"github.com/EternalVow/beyondIO/iouring"
	"github.com/EternalVow/beyondIO/socket"
	"github.com/baickl/logger"
	"io"
	"os"
	"runtime"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	errorx "github.com/panjf2000/gnet/v2/pkg/errors"
)

type eventloop struct {
	listeners    map[int]*listener // listeners
	idx          int               // loop index in the engine loops list
	cache        bytes.Buffer      // temporary buffer for scattered bytes
	engine       *engine           // engine in loop
	selector     Selector          // epoll or iouring
	buffer       []byte            // read packet buffer whose capacity is set by user, default value is 64KB
	connections  *Connections      // loop connections storage
	eventHandler EventHandler      // user eventHandler
}

func (el *eventloop) countConn() int32 {
	return int32(el.connections.GetCount())
}

func (el *eventloop) closeConns() {
	// Close loops and all outstanding connections
	for _, c := range el.connections.GetConnMap() {
		_ = el.close(c, nil)
	}
}

type connWithCallback struct {
	c  *conn
	cb func()
}

func (el *eventloop) register(itf interface{}) error {
	c, ok := itf.(*conn)
	if !ok {
		ccb := itf.(*connWithCallback)
		c = ccb.c
		defer ccb.cb()
	}
	return el.register0(c)
}

func (el *eventloop) register0(c *conn) error {
	addEvents := el.selector.AddRead
	//if el.engine.opts.EdgeTriggeredIO {
	//	addEvents = el.selector.AddReadWrite
	//}
	if err := addEvents(el.engine.ctx, c.fd, el.engine.opts.EdgeTriggeredIO); err != nil {
		_ = unix.Close(c.fd)
		c.release()
		return err
	}
	el.connections.AddConn(c)
	if c.isDatagram && c.remote != nil {
		return nil
	}
	return el.open(c)
}

func (el *eventloop) open(c *conn) error {
	c.opened = true

	err := el.eventHandler.OnConnect(c)
	if err != nil {
		return err
	}
	if err := c.open([]byte("OnConnect")); err != nil {
		return err
	}

	if !c.outboundBuffer.IsEmpty() && !el.engine.opts.EdgeTriggeredIO {
		if err := el.selector.ModReadWrite(el.engine.ctx, c.fd, false); err != nil {
			return err
		}
	}

	return nil
}

func (el *eventloop) read0(itf interface{}) error {
	return el.read(itf.(*conn))
}

const maxBytesTransferET = 1 << 20

func (el *eventloop) read(c *conn) error {
	if !c.opened {
		return nil
	}

	var recv int
	isET := el.engine.opts.EdgeTriggeredIO
loop:
	n, err := unix.Read(c.fd, el.buffer)
	if err != nil || n == 0 {
		if err == unix.EAGAIN {
			return nil
		}
		if n == 0 {
			err = io.EOF
		}
		return el.close(c, os.NewSyscallError("read", err))
	}
	recv += n

	c.buffer = el.buffer[:n]
	_, _ = c.inboundBuffer.Write(c.buffer)
	c.buffer = c.buffer[:0]

	if c.isEOF || (isET && recv < maxBytesTransferET) {
		goto loop
	}

	// To prevent infinite reading in ET mode and starving other events,
	// we need to set up threshold for the maximum read bytes per connection
	// on each event-loop. If the threshold is reached and there are still
	// unread data in the socket buffer, we must issue another read event manually.
	//if isET && n == len(el.buffer) {
	//	return el.selector.Trigger(queue.LowPriority, el.read0, c)
	//}

	return nil
}

func (el *eventloop) write0(itf interface{}) error {
	return el.write(itf.(*conn))
}

// The default value of UIO_MAXIOV/IOV_MAX is 1024 on Linux and most BSD-like OSs.
const iovMax = 1024

func (el *eventloop) write(c *conn) error {
	if c.outboundBuffer.IsEmpty() {
		return nil
	}

	isET := el.engine.opts.EdgeTriggeredIO
	var (
		n    int
		sent int
		err  error
	)
loop:
	iov, _ := c.outboundBuffer.Peek(-1)
	if len(iov) > 1 {
		if len(iov) > iovMax {
			iov = iov[:iovMax]
		}
		n, err = socket.Writev(c.fd, iov)
	} else {
		n, err = unix.Write(c.fd, iov[0])
	}
	_, _ = c.outboundBuffer.Discard(n)
	switch err {
	case nil:
	case unix.EAGAIN:
		return nil
	default:
		return el.close(c, os.NewSyscallError("write", err))
	}
	sent += n

	if isET && !c.outboundBuffer.IsEmpty() && sent < maxBytesTransferET {
		goto loop
	}

	// All data have been sent, it's no need to monitor the writable events for LT mode,
	// remove the writable event from selector to help the future event-loops if necessary.
	if !isET && c.outboundBuffer.IsEmpty() {
		return el.selector.ModRead(el.engine.ctx, c.fd, false)
	}

	// To prevent infinite writing in ET mode and starving other events,
	// we need to set up threshold for the maximum write bytes per connection
	// on each event-loop. If the threshold is reached and there are still
	// pending data to write, we must issue another write event manually.
	//if isET && !c.outboundBuffer.IsEmpty() {
	//	return el.selector.Trigger(queue.HighPriority, el.write0, c)
	//}

	return nil
}

func (el *eventloop) close(c *conn, err error) error {
	if !c.opened || el.connections.GetConnByFd(c.fd) == nil {
		return nil // ignore stale connections
	}

	el.connections.DelConn(c)
	err = el.eventHandler.OnClose(c, err)
	if err != nil {
		return err
	}

	// Send residual data in buffer back to the remote before actually closing the connection.
	for !c.outboundBuffer.IsEmpty() {
		iov, _ := c.outboundBuffer.Peek(0)
		if len(iov) > iovMax {
			iov = iov[:iovMax]
		}
		if n, e := socket.Writev(c.fd, iov); e != nil {
			break
		} else { //nolint:revive
			_, _ = c.outboundBuffer.Discard(n)
		}
	}

	c.release()

	var errStr strings.Builder
	err0, err1 := el.selector.Delete(c.fd), unix.Close(c.fd)
	if err0 != nil {
		err0 = fmt.Errorf("failed to delete fd=%d from selector in event-loop(%d): %v",
			c.fd, el.idx, os.NewSyscallError("delete", err0))
		errStr.WriteString(err0.Error())
		errStr.WriteString(" | ")
	}
	if err1 != nil {
		err1 = fmt.Errorf("failed to close fd=%d in event-loop(%d): %v",
			c.fd, el.idx, os.NewSyscallError("close", err1))
		errStr.WriteString(err1.Error())
	}
	if errStr.Len() > 0 {
		return errors.New(strings.TrimSuffix(errStr.String(), " | "))
	}

	return nil
}

func (el *eventloop) wake(c *conn) error {
	if !c.opened || el.connections.GetConnByFd(c.fd) == nil {
		return nil // ignore stale connections
	}

	//action := el.eventHandler.OnTraffic(c)

	return nil
}

func (el *eventloop) ticker(ctx context.Context) {
	var (
		delay time.Duration
		timer *time.Timer
	)
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()
	for {
		if timer == nil {
			timer = time.NewTimer(delay)
		} else {
			timer.Reset(delay)
		}
		select {
		case <-ctx.Done():
			logger.Debugf("stopping ticker in event-loop(%d) from Engine, error:%v", el.idx, ctx.Err())
			return
		case <-timer.C:
		}
	}
}

func (el *eventloop) readUDP(fd int) error {
	n, sa, err := unix.Recvfrom(fd, el.buffer, 0)
	if err != nil {
		if err == unix.EAGAIN {
			return nil
		}
		return fmt.Errorf("failed to read UDP packet from fd=%d in event-loop(%d), %v",
			fd, el.idx, os.NewSyscallError("recvfrom", err))
	}
	var c *conn
	if ln, ok := el.listeners[fd]; ok {
		c = newUDPConn(fd, el, ln.addr, sa, false)
	} else {
		c = el.connections.GetConnByFd(fd)
	}
	c.buffer = el.buffer[:n]
	//action := el.eventHandler.OnTraffic(c)
	//if c.remote != nil {
	//	c.release()
	//}
	//if action == Shutdown {
	//	return errorx.ErrEngineShutdown
	//}
	return nil
}

func (el *eventloop) accept0(fd int) error {
	for {
		nfd, sa, err := socket.Accept(fd)
		switch err {
		case nil:
		case unix.EAGAIN: // the Accept queue has been drained out, we can return now
			return nil
		case unix.EINTR, unix.ECONNRESET, unix.ECONNABORTED:
			// ECONNRESET or ECONNABORTED could indicate that a socket
			// in the Accept queue was closed before we Accept()ed it.
			// It's a silly error, let's retry it.
			continue
		default:
			logger.Errorf("Accept() failed due to error: %v", err)
			return ErrAcceptSocket
		}

		remoteAddr := socket.SockaddrToTCPOrUnixAddr(sa)
		if el.engine.opts.TCPKeepAlive > 0 && el.listeners[fd].network == "tcp" {
			err = socket.SetKeepAlivePeriod(nfd, int(el.engine.opts.TCPKeepAlive.Seconds()))
			if err != nil {
				logger.Errorf("failed to set TCP keepalive on fd=%d: %v", fd, err)
			}
		}

		//el := el.engine.eventLoops.next(remoteAddr)
		c := newTCPConn(nfd, el, sa, el.listeners[fd].addr, remoteAddr)
		err = el.register(c)
		if err != nil {
			logger.Errorf("failed to register the accepted socket fd=%d to selector: %v", c.fd, err)
			_ = unix.Close(nfd)
			c.release()
		}
	}
}

func (el *eventloop) accept(fd int) error {
	if el.listeners[fd].network == "udp" {
		return el.readUDP(fd)
	}

	nfd, sa, err := socket.Accept(fd)
	switch err {
	case nil:
	case unix.EINTR, unix.EAGAIN, unix.ECONNRESET, unix.ECONNABORTED:
		// ECONNRESET or ECONNABORTED could indicate that a socket
		// in the Accept queue was closed before we Accept()ed it.
		// It's a silly error, let's retry it.
		return nil
	default:
		logger.Errorf("Accept() failed due to error: %v", err)
		return ErrAcceptSocket
	}
	iouring.Submit(el.engine.ring.Ring)

	//iouring.SqeSetFlags(sqe, unix.Io)
	remoteAddr := socket.SockaddrToTCPOrUnixAddr(sa)
	if el.engine.opts.TCPKeepAlive > 0 && el.listeners[fd].network == "tcp" {
		err = socket.SetKeepAlivePeriod(nfd, int(el.engine.opts.TCPKeepAlive/time.Second))
		if err != nil {
			logger.Errorf("failed to set TCP keepalive on fd=%d: %v", fd, err)
		}
	}

	c := newTCPConn(nfd, el, sa, el.listeners[fd].addr, remoteAddr)
	return el.register0(c)
}

func (el *eventloop) rotate() error {
	if el.engine.opts.LockOSThread {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
	}

	err := el.selector.Polling(el.accept0)
	if errors.Is(err, errorx.ErrEngineShutdown) {
		logger.Debugf("main reactor is exiting in terms of the demand from user, %v", err)
		err = nil
	} else if err != nil {
		logger.Errorf("main reactor is exiting due to error: %v", err)
	}

	el.engine.shutdown(err)

	return err
}

func (el *eventloop) orbit() error {
	if el.engine.opts.LockOSThread {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
	}

	err := el.selector.Polling(func(fd int) error {
		c := el.connections.GetConnByFd(fd)
		if c == nil {
			// For kqueue, this might happen when the connection has already been closed,
			// the file descriptor will be deleted from kqueue automatically as documented
			// in the manual pages.
			// For epoll, it somehow notified with an event for a stale fd that is not in
			// our connection set. We need to explicitly delete it from the epoll set.
			// Also print a warning log for this kind of irregularity.
			logger.Warnf("received event[fd=%d] of a stale connection from event-loop(%d)", fd, el.idx)
			return el.selector.Delete(fd)
		}
		return nil
	})
	if errors.Is(err, errorx.ErrEngineShutdown) {
		logger.Debugf("event-loop(%d) is exiting in terms of the demand from user, %v", el.idx, err)
		err = nil
	} else if err != nil {
		logger.Errorf("event-loop(%d) is exiting due to error: %v", el.idx, err)
	}

	el.closeConns()
	el.engine.shutdown(err)

	return err
}

func (el *eventloop) run() error {
	if el.engine.opts.LockOSThread {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
	}

	err := el.selector.Polling(func(fd int) error {
		c := el.connections.GetConnByFd(fd)
		if c == nil {
			if _, ok := el.listeners[fd]; ok {
				return el.accept(fd)
			}
			// For kqueue, this might happen when the connection has already been closed,
			// the file descriptor will be deleted from kqueue automatically as documented
			// in the manual pages.
			// For epoll, it somehow notified with an event for a stale fd that is not in
			// our connection set. We need to explicitly delete it from the epoll set.
			// Also print a warning log for this kind of irregularity.
			logger.Warnf("received event[fd=%d] of a stale connection from event-loop(%d)", fd, el.idx)
			return el.selector.Delete(fd)
		}
		return nil
	})
	if errors.Is(err, errorx.ErrEngineShutdown) {
		logger.Debugf("event-loop(%d) is exiting in terms of the demand from user, %v", el.idx, err)
		err = nil
	} else if err != nil {
		logger.Errorf("event-loop(%d) is exiting due to error: %v", el.idx, err)
	}

	el.closeConns()
	el.engine.shutdown(err)

	return err
}
