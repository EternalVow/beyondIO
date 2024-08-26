package beyondIO

import (
	"context"
	"github.com/EternalVow/beyondIO/iouring"
	"github.com/EternalVow/beyondIO/socket"
	"github.com/baickl/logger"
	"github.com/panjf2000/gnet/v2/pkg/logging"
	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
	"net"
	"os"
	"runtime"
	"syscall"
	"time"
	"unsafe"
)

type OperationInfo struct {
	IOuringOpcode uint8

	Fd      int
	Addr    *net.Addr
	SysAddr *syscall.Sockaddr
	Iovec   *syscall.Iovec
}

type Selector interface {
	AddRead(ctx context.Context, fd int, edgeTriggered bool) error
	AddWrite(ctx context.Context, fd int, edgeTriggered bool) error
	ModRead(ctx context.Context, fd int, edgeTriggered bool) error
	ModReadWrite(ctx context.Context, fd int, edgeTriggered bool) error
	Delete(fd int) error
	Polling(el *eventloop, callback func(fd int) error) error
	//processIO(fd int) error
	WaitCqe(el *eventloop, callback func(fd int) error) error
}

type IoUringSelector struct {
	Ring     *engineRing
	EpollFd  int
	listenFd int
	network  string

	engine *engine
}

func NewIoUringSelector(engine *engine) *IoUringSelector {
	return &IoUringSelector{
		engine: engine,
		Ring:   &engine.ring,
		//network: network,
	}
}

func (s IoUringSelector) AddRead(ctx context.Context, fd int, edgeTriggered bool) error {
	var ev uint32
	if edgeTriggered {
		ev |= unix.EPOLLET | unix.EPOLLRDHUP
	}
	return os.NewSyscallError("epoll_ctl add",
		unix.EpollCtl(s.EpollFd, unix.EPOLL_CTL_ADD, fd, &unix.EpollEvent{Fd: int32(fd), Events: ev}))

}

// AddWrite registers the given file-descriptor with writable event to the selector.
func (s IoUringSelector) AddWrite(ctx context.Context, fd int, edgeTriggered bool) error {
	var ev uint32
	if edgeTriggered {
		ev |= unix.EPOLLET | unix.EPOLLRDHUP
	}
	return os.NewSyscallError("epoll_ctl add",
		unix.EpollCtl(s.EpollFd, unix.EPOLL_CTL_ADD, fd, &unix.EpollEvent{Fd: int32(fd), Events: ev}))
}

// ModRead renews the given file-descriptor with readable event in the selector.
func (s IoUringSelector) ModRead(ctx context.Context, fd int, edgeTriggered bool) error {
	var ev uint32
	if edgeTriggered {
		ev |= unix.EPOLLET | unix.EPOLLRDHUP
	}
	return os.NewSyscallError("epoll_ctl mod",
		unix.EpollCtl(s.EpollFd, unix.EPOLL_CTL_MOD, fd, &unix.EpollEvent{Fd: int32(fd), Events: ev}))
}

// ModReadWrite renews the given file-descriptor with readable and writable events in the selector.
func (s IoUringSelector) ModReadWrite(ctx context.Context, fd int, edgeTriggered bool) error {
	var ev uint32
	if edgeTriggered {
		ev |= unix.EPOLLET | unix.EPOLLRDHUP
	}
	return os.NewSyscallError("epoll_ctl mod",
		unix.EpollCtl(s.EpollFd, unix.EPOLL_CTL_MOD, fd, &unix.EpollEvent{Fd: int32(fd), Events: ev}))
}

// Delete removes the given file-descriptor from the selector.
func (s IoUringSelector) Delete(fd int) error {
	return os.NewSyscallError("epoll_ctl del", unix.EpollCtl(s.EpollFd, unix.EPOLL_CTL_DEL, fd, nil))
}

// Polling blocks the current goroutine, waiting for network-events.
func (s IoUringSelector) Polling(el *eventloop, callback func(fd int) error) error {
	events := make([]unix.EpollEvent, MAX_EVENTS)
	msec := -1
	for {
		n, err := unix.EpollWait(s.EpollFd, events, msec)
		if n == 0 || (n < 0 && err == unix.EINTR) {
			msec = -1
			runtime.Gosched()
			continue
		} else if err != nil {
			logging.Errorf("error occurs in epoll: %v", os.NewSyscallError("epoll_wait", err))
			return err
		}
		msec = 0

		for i := 0; i < n; i++ {

			ev := &events[i]
			fd := int(ev.Fd)
			addr, err := socket.NewSockAddrBySys(s.engine.listeners[fd].network)
			if err != nil {
				return err
			}
			switch fd {
			case s.listenFd:
				remoteAddr := socket.SockaddrToTCPOrSysAddr(addr)

				sqe := s.Ring.GetSqe(s.Ring.Ring)
				operationInfo := &OperationInfo{
					IOuringOpcode: iouring.OpAccept,
					Fd:            fd,
					Addr:          &remoteAddr,
					SysAddr:       &addr,
				}
				sqe.UserData = uint64(uintptr(unsafe.Pointer(operationInfo)))
				err = s.Ring.PrepAccept(sqe, fd, &addr, 0, 0)
				if err != nil {
					return err
				}
				s.Ring.Submit(s.Ring.Ring)

			case s.EpollFd:

			default:
				if ev.Events&unix.EPOLLIN != 0 {
					// read
					sqe := s.Ring.GetSqe(s.Ring.Ring)
					operationInfo := &OperationInfo{IOuringOpcode: iouring.OpRead}
					sqe.UserData = uint64(uintptr(unsafe.Pointer(operationInfo)))

					bf := make([]byte, DefaultBufferSize)
					iovec := &syscall.Iovec{
						Base: &bf[0],
						Len:  uint64(DefaultBufferSize),
					}
					err := s.Ring.PrepReadv(sqe, fd, iovec, 0, 0)
					if err != nil {
						return err
					}
					s.Ring.Submit(s.Ring.Ring)
				} else if ev.Events&unix.EPOLLOUT != 0 {
					//write
					sqe := s.Ring.GetSqe(s.Ring.Ring)
					operationInfo := &OperationInfo{IOuringOpcode: iouring.OpWrite}
					sqe.UserData = uint64(uintptr(unsafe.Pointer(operationInfo)))
					iov, _ := el.connections.ConnMap[fd].outboundBuffer.Peek(-1)
					if len(iov) > 1 {
						if len(iov) > iovMax {
							iov = iov[:iovMax]
						}
					}
					iovecs := make([]unix.Iovec, 0, minIovec)
					iovecs = socket.AppendBytes(iovecs, iov)
					sysIovec := (*syscall.Iovec)(unsafe.Pointer(&iovecs[0]))
					err := s.Ring.PrepWritev(sqe, fd, sysIovec, 0, 0)
					if err != nil {
						return err
					}
					s.Ring.Submit(s.Ring.Ring)
				}
			}
		}
		// cqe wait
		err = s.WaitCqe(el, callback)
		if err != nil {
			return err
		}

	}
}

func (s IoUringSelector) WaitCqe(el *eventloop, callback func(fd int) error) error {
	cqe := &iouring.CompletionQueueEvent{}
	ret, err := s.Ring.WaitCqe(s.Ring.Ring, &cqe)
	if err != nil {
		return err
	}
	if ret < 0 {
		return errors.New("wait cqe failed")
	}
	if cqe.Res < 0 {
		logging.Errorf("wait cqe completion failed")
	} else {
		operationInfo := (*OperationInfo)(unsafe.Pointer(uintptr(cqe.UserData)))

		switch operationInfo.IOuringOpcode {
		case iouring.OpAccept:
			nfd := int(cqe.Res)
			if s.engine.opts.TCPKeepAlive > 0 && s.engine.listeners[operationInfo.Fd].network == "tcp" {
				err = socket.SetKeepAlivePeriod(nfd, int(s.engine.opts.TCPKeepAlive/time.Second))
				if err != nil {
					logger.Errorf("failed to set TCP keepalive on fd=%d: %v", operationInfo.Fd, err)
				}
			}
			ua := socket.TranSyscallSockaddrToUnixAddr(*operationInfo.SysAddr)
			c := newTCPConn(nfd, el, ua, s.engine.listeners[operationInfo.Fd].addr, *operationInfo.Addr)
			err := el.register0(c)
			if err != nil {
				return err
			}
		case iouring.OpRead:

			c := el.connections.GetConnMap()[operationInfo.Fd]
			if c == nil {
				return errors.New("no connection found for this fd")
			}

			c.buffer = *(*[]byte)(unsafe.Pointer(operationInfo.Iovec.Base))
			_, _ = c.inboundBuffer.Write(c.buffer)
			c.buffer = c.buffer[:0]

		case iouring.OpWrite:
			c := el.connections.GetConnMap()[operationInfo.Fd]
			_, _ = c.outboundBuffer.Discard(int(cqe.Res))

		default:

		}
	}

	s.Ring.CqeSeen(s.Ring.Ring, cqe)

	return nil
}
