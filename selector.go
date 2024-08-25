package beyondIO

import (
	"context"
	"github.com/EternalVow/beyondIO/iouring"
	"github.com/EternalVow/beyondIO/socket"
	"github.com/panjf2000/gnet/v2/pkg/logging"
	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
	"github.com/mohae/deepcopy"
	"io"
	"os"
	"runtime"
	"syscall"
)

type Selector interface {
	AddRead(ctx context.Context,fd int , edgeTriggered bool) error
    AddWrite(ctx context.Context,fd int , edgeTriggered bool) error
	ModRead(ctx context.Context,fd int , edgeTriggered bool) error
	ModReadWrite(ctx context.Context,fd int , edgeTriggered bool) error
	Delete(fd int) error
	Polling(callback func(fd int)error) error
	//processIO(fd int) error

}

type IoUringSelector struct {
	Ring *engineRing
	EpollFd int
	listenFd int
	network string

	engine *engine

}

func NewIoUringSelector(engine *engine) *IoUringSelector  {
	return &IoUringSelector{
		engine: engine,
		Ring: &Ring,
		//network: network,
	}
}

func (s IoUringSelector) AddRead(ctx context.Context,fd int , edgeTriggered bool) error {
	var ev uint32
	if edgeTriggered {
		ev |= unix.EPOLLET | unix.EPOLLRDHUP
	}
	return os.NewSyscallError("epoll_ctl add",
		unix.EpollCtl(s.EpollFd, unix.EPOLL_CTL_ADD, fd, &unix.EpollEvent{Fd: int32(fd), Events: ev}))

}


// AddWrite registers the given file-descriptor with writable event to the selector.
func (s IoUringSelector) AddWrite(ctx context.Context,fd int , edgeTriggered bool) error {
	var ev uint32 
	if edgeTriggered {
		ev |= unix.EPOLLET | unix.EPOLLRDHUP
	}
	return os.NewSyscallError("epoll_ctl add",
		unix.EpollCtl(s.EpollFd, unix.EPOLL_CTL_ADD, fd, &unix.EpollEvent{Fd: int32(fd), Events: ev}))
}

// ModRead renews the given file-descriptor with readable event in the selector.
func (s IoUringSelector) ModRead(ctx context.Context,fd int , edgeTriggered bool) error {
	var ev uint32
	if edgeTriggered {
		ev |= unix.EPOLLET | unix.EPOLLRDHUP
	}
	return os.NewSyscallError("epoll_ctl mod",
		unix.EpollCtl(s.EpollFd, unix.EPOLL_CTL_MOD, fd, &unix.EpollEvent{Fd: int32(fd), Events: ev}))
}

// ModReadWrite renews the given file-descriptor with readable and writable events in the selector.
func (s IoUringSelector) ModReadWrite(ctx context.Context,fd int , edgeTriggered bool) error {
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
func (s IoUringSelector) Polling(callback func(fd int)error) error {
	events := make( []unix.EpollEvent,MAX_EVENTS)
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
			addr,err :=  socket.NewSockAddrBySys(s.engine.listeners[0].network)
			if err != nil {
				return err
			}
			ev := &events[i]
			fd := int(ev.Fd)
			switch fd {
			case s.listenFd:
				sqe := s.Ring.GetSqe(s.Ring.Ring)
				//sqe := &iouring.SubmissionQueueEntry{}
				err = s.Ring.PrepAccept(sqe, fd, &addr, 0, 0)
				if err != nil {
					return err
				}
				s.Ring.Submit(s.Ring.Ring)

			case s.EpollFd:

			default:
				if ev.Events & unix.EPOLLIN != 0 {
					// read
					sqe := s.Ring.GetSqe(s.Ring.Ring)
					//sqe := &iouring.SubmissionQueueEntry{}

					err := s.Ring.PrepRead(sqe, fd,nil, 0, 0)
					if err != nil {
						return err
					}
					s.Ring.Submit(s.Ring.Ring)
				}else if ev.Events & unix.EPOLLOUT != 0 {
					//write
					// read
					sqe := s.Ring.GetSqe(s.Ring.Ring)
					//sqe := &iouring.SubmissionQueueEntry{}
					err := s.Ring.PrepWrite(sqe, fd, nil, 0, 0)
					if err != nil {
						return err
					}
					s.Ring.Submit(s.Ring.Ring)
				}
			}
		}
		// cqe wait
		err=s.WaitCqe(callback)
		if err != nil {
			return err
		}

	}
}


func (s IoUringSelector) WaitCqe(callback func(fd int)error) error{
	cqe := &iouring.CompletionQueueEvent{}
	ret,err:= s.Ring.WaitCqe(s.Ring.Ring,&cqe)
	if err != nil {
		return err
	}
	if ret < 0 {
		return errors.New("wait cqe failed")
	}
	if cqe.Res < 0 {
		logging.Errorf("wait cqe completion failed")
	}else {
		 if cqe.UserData == 0 {
			 if callback == eventloop.accept0 {

			 }
			 handle_accept(ctx, cqe);
		 }else {

			 handle_read(ctx, cqe, (int)cqe->user_data);
		 }
	}

	s.Ring.CqeSeen(s.Ring.Ring,cqe)

	return nil
}

//
//#include <stdio.h>
//#include <stdlib.h>
//#include <string.h>
//#include <unistd.h>
//#include <sys/socket.h>
//#include <netinet/in.h>
//#include <arpa/inet.h>
//#include <liburing.h>
//#include <sys/epoll.h>
//
//#define PORT 8888
//#define BUFFER_SIZE 1024
//#define MAX_EVENTS 10
//
//struct server_context {
//struct io_uring ring;
//int epoll_fd;
//int listen_fd;
//};
//
//
//void handle_read(struct server_context *ctx, struct io_uring_cqe *cqe, int client_fd) {
//char buffer[BUFFER_SIZE];
//ssize_t bytes_read = read(client_fd, buffer, BUFFER_SIZE);
//if (bytes_read <= 0) {
//if (bytes_read == 0) {
//// 连接关闭
//printf("Client disconnected\n");
//} else {
//perror("read");
//}
//close(client_fd);
//return;
//}
//
//// 在这里可以处理接收到的数据
//// 例如，简单地回显数据
//write(client_fd, buffer, bytes_read);
//}
//
//void setup_server(struct server_context *ctx) {
//ctx->listen_fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
//if (ctx->listen_fd < 0) {
//perror("socket");
//exit(EXIT_FAILURE);
//}
//
//struct sockaddr_in server_addr;
//memset(&server_addr, 0, sizeof(server_addr));
//server_addr.sin_family = AF_INET;
//server_addr.sin_addr.s_addr = INADDR_ANY;
//server_addr.sin_port = htons(PORT);
//
//if (bind(ctx->listen_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
//perror("bind");
//exit(EXIT_FAILURE);
//}
//
//if (listen(ctx->listen_fd, SOMAXCONN) < 0) {
//perror("listen");
//exit(EXIT_FAILURE);
//}
//
//// 初始化 io_uring
//if (io_uring_queue_init(8, &ctx->ring, 0) < 0) {
//perror("io_uring_queue_init");
//exit(EXIT_FAILURE);
//}
//
//// 创建 epoll 实例
//ctx->epoll_fd = epoll_create1(0);
//if (ctx->epoll_fd == -1) {
//perror("epoll_create1");
//exit(EXIT_FAILURE);
//}
//
//// 将监听套接字添加到 epoll 实例中
//struct epoll_event event;
//event.events = EPOLLIN | EPOLLET;
//event.data.fd = ctx->listen_fd;
//if (epoll_ctl(ctx->epoll_fd, EPOLL_CTL_ADD, ctx->listen_fd, &event) == -1) {
//perror("epoll_ctl");
//exit(EXIT_FAILURE);
//}
//}
//
//void run_server(struct server_context *ctx) {
//struct io_uring_cqe *cqe;
//struct epoll_event events[MAX_EVENTS];
//int running = 1;
//
//while (running) {
//int event_count = epoll_wait(ctx->epoll_fd, events, MAX_EVENTS, -1);
//if (event_count == -1) {
//perror("epoll_wait");
//break;
//}
//
//for (int i = 0; i < event_count; i++) {
//if (events[i].data.fd == ctx->listen_fd) {
//// 有新连接
//struct io_uring_sqe *sqe = io_uring_get_sqe(&ctx->ring);
//io_uring_prep_accept(sqe, ctx->listen_fd, NULL, NULL, 0);
//io_uring_sqe_set_flags(sqe, IOSQE_ASYNC);
//io_uring_submit(&ctx->ring);
//} else {
//// 有数据可读
//struct io_uring_sqe *sqe = io_uring_get_sqe(&ctx->ring);
//io_uring_prep_read(sqe, events[i].data.fd, NULL, BUFFER_SIZE, 0);
//io_uring_sqe_set_flags(sqe, IOSQE_ASYNC);
//io_uring_submit(&ctx->ring);
//}
//}
//
//int ret = io_uring_wait_cqe(&ctx->ring, &cqe);
//if (ret < 0) {
//perror("io_uring_wait_cqe");
//break;
//}
//
//if (cqe->res < 0) {
//perror("io_uring completion error");
//} else {
//if (cqe->user_data == 0) {
//handle_accept(ctx, cqe);
//} else {
//handle_read(ctx, cqe, (int)cqe->user_data);
//}
//}
//
//io_uring_cqe_seen(&ctx->ring, cqe);
//}
//}
//
//void cleanup_server(struct server_context *ctx) {
//close(ctx->listen_fd);
//io_uring_queue_exit(&ctx->ring);
//close(ctx->epoll_fd);
//}
//
//int main() {
//struct server_context ctx;
//setup_server(&ctx);
//run_server(&ctx);
//cleanup_server(&ctx);
//return 0;
//}