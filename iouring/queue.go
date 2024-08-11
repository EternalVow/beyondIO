package iouring

import (
	"errors"
	"syscall"
	"unsafe"
)

func PrepRw(op int, sqe *SubmissionQueueEntry, fd int, addr unsafe.Pointer, len uint32, offset uint64) error {
	if sqe == nil {
		return errors.New("sqe is nil")
	}
	sqe.OpCode = uint8(op)
	sqe.Fd = int32(fd)
	sqe.Off = offset
	sqe.Addr = *(*uint64)(addr)
	sqe.Len = len

	return nil
}

func SqeSetData(sqe *SubmissionQueueEntry, data uint64) error {
	if sqe == nil {
		return errors.New("sqe is nil")
	}

	sqe.UserData = data

	return nil
}

func InitializeSqe() *SubmissionQueueEntry {
	sqe := &SubmissionQueueEntry{}
	return sqe
}

func SqeSetFlags(sqe *SubmissionQueueEntry, flags uint8) error {
	if sqe == nil {
		return errors.New("sqe is nil")
	}

	sqe.Flags = flags

	return nil
}

func PrepSplice(sqe *SubmissionQueueEntry, fd_in int, off_in int, fd_out int, off_out int, nbytes uint32, splice_flags uint) error {
	err := PrepRw(int(OpSplice), sqe, fd_out, nil, nbytes, uint64(fd_out))
	if err != nil {
		return err
	}
	sqe.SpliceOffIn = int32(off_in)
	sqe.SpliceFdIn = int32(fd_in)
	sqe.SpliceFlags = int32(splice_flags)

	return nil
}

func PrepTree(sqe *SubmissionQueueEntry, fd_in int, fd_out int, nbytes uint32, splice_flags uint) error {
	err := PrepRw(int(OpTee), sqe, fd_out, nil, nbytes, 0)
	if err != nil {
		return err
	}
	sqe.SpliceOffIn = int32(0)
	sqe.SpliceFdIn = int32(fd_in)
	sqe.SpliceFlags = int32(splice_flags)

	return nil
}

func PrepReadv(sqe *SubmissionQueueEntry, fd int, iovec *syscall.Iovec, nr_vecs uint32, offset uint64) error {
	err := PrepRw(int(OpReadv), sqe, fd, unsafe.Pointer(iovec), nr_vecs, 0)
	if err != nil {
		return err
	}

	return nil
}

func PrepReadv2(sqe *SubmissionQueueEntry, fd int, iovec *syscall.Iovec, nr_vecs uint32, offset uint64, flags int) error {
	err := PrepReadv(sqe, fd, iovec, nr_vecs, offset)
	if err != nil {
		return err
	}
	sqe.RwFlags = uint8(flags)

	return nil
}

func PrepReadFixed(sqe *SubmissionQueueEntry, fd int, buf unsafe.Pointer, nbytes uint32, offset uint64, buf_index int) error {
	err := PrepRw(int(OpReadFixed), sqe, fd, buf, nbytes, offset)
	if err != nil {
		return err
	}
	sqe.BufIndex = uint64(buf_index)

	return nil
}

func PrepReadWritev(sqe *SubmissionQueueEntry, fd int, iovec *syscall.Iovec, nr_vecs uint32, offset uint64) error {
	err := PrepRw(int(OpWritev), sqe, fd, unsafe.Pointer(iovec), nr_vecs, offset)
	if err != nil {
		return err
	}
	return nil
}

func PrepReadWritev2(sqe *SubmissionQueueEntry, fd int, iovec *syscall.Iovec, nr_vecs uint32, offset uint64, flags int) error {
	err := PrepReadWritev(sqe, fd, iovec, nr_vecs, offset)
	if err != nil {
		return err
	}
	return nil
}

func PrepWriteFixed(sqe *SubmissionQueueEntry, fd int, buf unsafe.Pointer, nbytes uint32, offset uint64, buf_index int) error {
	err := PrepRw(int(OpWriteFixed), sqe, fd, buf, nbytes, offset)
	if err != nil {
		return err
	}
	sqe.BufIndex = uint64(buf_index)

	return nil
}

func PrepRecvmsg(sqe *SubmissionQueueEntry, fd int, msgh *syscall.Msghdr, flags int) error {
	err := PrepRw(int(OpRecvmsg), sqe, fd, unsafe.Pointer(msgh), 1, 0)
	if err != nil {
		return err
	}
	sqe.MsgFlags = uint8(flags)

	return nil
}

func PrepRecvmsgMultishot(sqe *SubmissionQueueEntry, fd int, msgh *syscall.Msghdr, flags int) error {
	err := PrepRecvmsg(sqe, fd, msgh, flags)
	if err != nil {
		return err
	}
	sqe.IoPrio |= RecvMultishot

	return nil
}

func PrepSendmsg(sqe *SubmissionQueueEntry, fd int, msgh *syscall.Msghdr, flags int) error {
	err := PrepRw(int(OpSendmsg), sqe, fd, unsafe.Pointer(msgh), 1, 0)
	if err != nil {
		return err
	}
	sqe.MsgFlags = uint8(flags)

	return nil
}

func PrepAccept(sqe *SubmissionQueueEntry, fd int, addr *syscall.Sockaddr, addrlen uint64, flags int) error {
	err := PrepRw(int(OpAccept), sqe, fd, unsafe.Pointer(addr), 1, addrlen)
	if err != nil {
		return err
	}
	sqe.AcceptFlags = uint8(flags)

	return nil
}

func SetTarGetFixedFile(sqe *SubmissionQueueEntry, file_index uint32) error {

	sqe.FileIndex = file_index
	return nil
}

func PrepAcceptDirect(sqe *SubmissionQueueEntry, fd int, addr *syscall.Sockaddr, addrlen uint64, flags int, file_index uint32) error {
	err := PrepAccept(sqe, fd, addr, addrlen, flags)
	if err != nil {
		return err
	}
	if file_index == FileIndexAlloc {
		file_index--
	}

	SetTarGetFixedFile(sqe, file_index)

	return nil
}

func PrepMultishotAccept(sqe *SubmissionQueueEntry, fd int, addr *syscall.Sockaddr, addrlen uint64, flags int) error {
	err := PrepAccept(sqe, fd, addr, addrlen, flags)
	if err != nil {
		return err
	}
	sqe.IoPrio |= AcceptMultishot

	return nil
}

func PrepMultishotAcceptDirect(sqe *SubmissionQueueEntry, fd int, addr *syscall.Sockaddr, addrlen uint64, flags int) error {
	err := PrepMultishotAccept(sqe, fd, addr, addrlen, flags)
	if err != nil {
		return err
	}

	SetTarGetFixedFile(sqe, -1)

	return nil
}

func PrepCancel64(sqe *SubmissionQueueEntry, user_data uint64, flags int) error {
	err := PrepRw(int(OpAsyncCancel), sqe, -1, nil, 0, 0)
	if err != nil {
		return err
	}
	sqe.Addr = user_data
	sqe.CancelFlags = uint32(flags)

	return nil
}

func PrepCancel(sqe *SubmissionQueueEntry, user_data unsafe.Pointer, flags int) error {
	return PrepCancel64(sqe, *(*uint64)(user_data), flags)
}

func PrepCancelFd(sqe *SubmissionQueueEntry, fd int, flags uint) error {
	err := PrepRw(int(OpAsyncCancel), sqe, fd, nil, 0, 0)
	if err != nil {
		return err
	}
	sqe.CancelFlags = uint32(flags) | AsyncCancelFd

	return nil
}

func PrepConnect(sqe *SubmissionQueueEntry, fd int, addr *syscall.Sockaddr, addrlen uint64) error {
	err := PrepRw(int(OpConnect), sqe, fd, unsafe.Pointer(addr), 0, addrlen)
	if err != nil {
		return err
	}

	return nil
}

func PrepBind(sqe *SubmissionQueueEntry, fd int, addr *syscall.Sockaddr, addrlen uint64) error {
	err := PrepRw(int(OpBind), sqe, fd, unsafe.Pointer(addr), 0, addrlen)
	if err != nil {
		return err
	}

	return nil
}

func PrepListen(sqe *SubmissionQueueEntry, fd int, backlog uint32) error {
	err := PrepRw(int(OpListen), sqe, fd, nil, backlog, 0)
	if err != nil {
		return err
	}

	return nil
}

//func PrepFilesUpdate(sqe *SubmissionQueueEntry, fds []int, nr_fds uint32,offset uint) error {
//	err := PrepRw(int(OpFilesUpdate), sqe, -1, unsafe.Pointer(fds), nr_fds, 0)
//	if err != nil {
//		return err
//	}
//
//	return nil
//}

func PrepFallocate(sqe *SubmissionQueueEntry, fd int, mode int, offset uint64, len uint64) error {
	err := PrepRw(int(OpFallocate), sqe, fd, nil, uint32(mode), offset)
	if err != nil {
		return err
	}
	sqe.Addr = len

	return nil
}

func PrepClose(sqe *SubmissionQueueEntry, fd int) error {
	err := PrepRw(int(OpClose), sqe, fd, nil, 0, 0)
	if err != nil {
		return err
	}

	return nil
}

func PrepCloseDirect(sqe *SubmissionQueueEntry, file_index uint32) error {
	err := PrepClose(sqe, 0)
	if err != nil {
		return err
	}
	SetTarGetFixedFile(sqe, file_index)

	return nil
}

func PrepRead(sqe *SubmissionQueueEntry, fd int, buf unsafe.Pointer, nbytes uint32, offset uint64) error {
	err := PrepRw(int(OpRead), sqe, fd, buf, nbytes, offset)
	if err != nil {
		return err
	}

	return nil
}

func PrepReadMultishot(sqe *SubmissionQueueEntry, fd int, nbytes uint32, offset uint64, buf_group uint64) error {
	err := PrepRw(int(OpReadMultishot), sqe, fd, nil, nbytes, offset)
	if err != nil {
		return err
	}
	sqe.BufGroup = buf_group
	return nil
}

func PrepReadWrite(sqe *SubmissionQueueEntry, fd int, buf unsafe.Pointer, nbytes uint32, offset uint64) error {
	err := PrepRw(int(OpWrite), sqe, fd, buf, nbytes, offset)
	if err != nil {
		return err
	}
	return nil
}

func PrepReadSend(sqe *SubmissionQueueEntry, sockfd int, buf unsafe.Pointer, len uint32, flags int) error {
	err := PrepRw(int(OpSend), sqe, sockfd, buf, len, 0)
	if err != nil {
		return err
	}
	sqe.MsgFlags = uint8(flags)
	return nil
}

func PrepReadBundle(sqe *SubmissionQueueEntry, sockfd int, len uint32, flags int) error {
	err := PrepReadSend(sqe, sockfd, nil, len, flags)
	if err != nil {
		return err
	}
	sqe.IoPrio |= RecvsendBundle
	return nil
}

func PrepSendSetAddr(sqe *SubmissionQueueEntry, dest_addr *syscall.Sockaddr, addr_len uint64) error {
	sqe.Addr2 = *(*uint64)(unsafe.Pointer(dest_addr))
	sqe.AddrLen = addr_len
	return nil
}

func PrepReadSendto(sqe *SubmissionQueueEntry, sockfd int, buf unsafe.Pointer, len uint32, flags int, addr *syscall.Sockaddr, addr_len uint64) error {
	err := PrepReadSend(sqe, sockfd, buf, len, flags)
	if err != nil {
		return err
	}
	err = PrepSendSetAddr(sqe, addr, addr_len)
	if err != nil {
		return err
	}
	return nil
}

func PrepReadSendZc(sqe *SubmissionQueueEntry, sockfd int, buf unsafe.Pointer, len uint32, flags int, zc_flags uint16) error {
	err := PrepRw(int(OpSendZC), sqe, sockfd, buf, len, 0)
	if err != nil {
		return err
	}
	sqe.MsgFlags = uint8(flags)
	sqe.IoPrio = zc_flags
	return nil
}

func PrepReadSendZcFixed(sqe *SubmissionQueueEntry, sockfd int, buf unsafe.Pointer, len uint32, flags int, zc_flags uint16, buf_index int) error {

	err := PrepReadSendZc(sqe, sockfd, buf, len, flags, zc_flags)
	if err != nil {
		return err
	}
	sqe.IoPrio |= RecvsendFixedBuf
	sqe.BufIndex = uint64(buf_index)

	return nil
}

func PrepSendmsgZc(sqe *SubmissionQueueEntry, fd int, msgh *syscall.Msghdr, flags int) error {

	err := PrepSendmsg(sqe, fd, msgh, flags)
	if err != nil {
		return err
	}
	sqe.OpCode = OpSendMsgZC

	return nil
}

func PrepRecv(sqe *SubmissionQueueEntry, sockfd int, buf unsafe.Pointer, len uint32, flags int) error {
	err := PrepRw(int(OpReadv), sqe, sockfd, buf, len, 0)
	if err != nil {
		return err
	}
	sqe.MsgFlags = uint8(flags)
	return nil
}

func PrepRecvMultishot(sqe *SubmissionQueueEntry, sockfd int, buf unsafe.Pointer, len uint32, flags int) error {
	err := PrepRecv(sqe, sockfd, buf, len, flags)
	if err != nil {
		return err
	}
	sqe.IoPrio |= RecvMultishot
	return nil
}

// struct epoll_event;
// IOURINGINLINE void io_uring_prep_epoll_ctl(struct io_uring_sqe *sqe, int epfd,
// int fd, int op,
// struct epoll_event *ev)
// {
// io_uring_prep_rw(IORING_OP_EPOLL_CTL, sqe, epfd, ev,
// (__u32) op, (__u32) fd);
// }
//
// IOURINGINLINE void io_uring_prep_provide_buffers(struct io_uring_sqe *sqe,
// void *addr, int len, int nr,
// int bgid, int bid)
// {
// io_uring_prep_rw(IORING_OP_PROVIDE_BUFFERS, sqe, nr, addr, (__u32) len,
// (__u64) bid);
// sqe->buf_group = (__u16) bgid;
// }
//
// IOURINGINLINE void io_uring_prep_remove_buffers(struct io_uring_sqe *sqe,
// int nr, int bgid)
// {
// io_uring_prep_rw(IORING_OP_REMOVE_BUFFERS, sqe, nr, NULL, 0, 0);
// sqe->buf_group = (__u16) bgid;
// }
//
// IOURINGINLINE void io_uring_prep_shutdown(struct io_uring_sqe *sqe, int fd,
// int how)
// {
// io_uring_prep_rw(IORING_OP_SHUTDOWN, sqe, fd, NULL, (__u32) how, 0);
// }
//
// IOURINGINLINE void io_uring_prep_unlinkat(struct io_uring_sqe *sqe, int dfd,
// const char *path, int flags)
// {
// io_uring_prep_rw(IORING_OP_UNLINKAT, sqe, dfd, path, 0, 0);
// sqe->unlink_flags = (__u32) flags;
// }
//
// IOURINGINLINE void io_uring_prep_unlink(struct io_uring_sqe *sqe,
// const char *path, int flags)
// {
// io_uring_prep_unlinkat(sqe, AT_FDCWD, path, flags);
// }
// struct epoll_event;
// IOURINGINLINE void io_uring_prep_epoll_ctl(struct io_uring_sqe *sqe, int epfd,
// int fd, int op,
// struct epoll_event *ev)
// {
// io_uring_prep_rw(IORING_OP_EPOLL_CTL, sqe, epfd, ev,
// (__u32) op, (__u32) fd);
// }
//
// IOURINGINLINE void io_uring_prep_provide_buffers(struct io_uring_sqe *sqe,
// void *addr, int len, int nr,
// int bgid, int bid)
// {
// io_uring_prep_rw(IORING_OP_PROVIDE_BUFFERS, sqe, nr, addr, (__u32) len,
// (__u64) bid);
// sqe->buf_group = (__u16) bgid;
// }
//
// IOURINGINLINE void io_uring_prep_remove_buffers(struct io_uring_sqe *sqe,
// int nr, int bgid)
// {
// io_uring_prep_rw(IORING_OP_REMOVE_BUFFERS, sqe, nr, NULL, 0, 0);
// sqe->buf_group = (__u16) bgid;
// }
//
// IOURINGINLINE void io_uring_prep_shutdown(struct io_uring_sqe *sqe, int fd,
// int how)
// {
// io_uring_prep_rw(IORING_OP_SHUTDOWN, sqe, fd, NULL, (__u32) how, 0);
// }
//
// IOURINGINLINE void io_uring_prep_unlinkat(struct io_uring_sqe *sqe, int dfd,
// const char *path, int flags)
// {
// io_uring_prep_rw(IORING_OP_UNLINKAT, sqe, dfd, path, 0, 0);
// sqe->unlink_flags = (__u32) flags;
// }
//
// IOURINGINLINE void io_uring_prep_unlink(struct io_uring_sqe *sqe,
// const char *path, int flags)
// {
// io_uring_prep_unlinkat(sqe, AT_FDCWD, path, flags);
// }
//
// IOURINGINLINE void io_uring_prep_socket(struct io_uring_sqe *sqe, int domain,
// int type, int protocol,
// unsigned int flags)
// {
// io_uring_prep_rw(IORING_OP_SOCKET, sqe, domain, NULL, protocol, type);
// sqe->rw_flags = flags;
// }
//
// IOURINGINLINE void io_uring_prep_socket_direct(struct io_uring_sqe *sqe,
// int domain, int type,
// int protocol,
// unsigned file_index,
// unsigned int flags)
// {
// io_uring_prep_rw(IORING_OP_SOCKET, sqe, domain, NULL, protocol, type);
// sqe->rw_flags = flags;
// /* offset by 1 for allocation */
// if (file_index == IORING_FILE_INDEX_ALLOC)
// file_index--;
// __io_uring_set_target_fixed_file(sqe, file_index);
// }
//
// IOURINGINLINE void io_uring_prep_socket_direct_alloc(struct io_uring_sqe *sqe,
// int domain, int type,
// int protocol,
// unsigned int flags)
// {
// io_uring_prep_rw(IORING_OP_SOCKET, sqe, domain, NULL, protocol, type);
// sqe->rw_flags = flags;
// __io_uring_set_target_fixed_file(sqe, IORING_FILE_INDEX_ALLOC - 1);
// }
//
// /*
// * Returns how many unconsumed entries are ready in the CQ ring
// */
// IOURINGINLINE unsigned io_uring_cq_ready(const struct io_uring *ring)
// {
// return io_uring_smp_load_acquire(ring->cq.ktail) - *ring->cq.khead;
// }
//
// /*
// * Returns true if there are overflow entries waiting to be flushed onto
// * the CQ ring
// */
// IOURINGINLINE bool io_uring_cq_has_overflow(const struct io_uring *ring)
// {
// return IO_URING_READ_ONCE(*ring->sq.kflags) & IORING_SQ_CQ_OVERFLOW;
// }
//
// /*
// * Returns true if the eventfd notification is currently enabled
// */
// IOURINGINLINE bool io_uring_cq_eventfd_enabled(const struct io_uring *ring)
// {
// if (!ring->cq.kflags)
// return true;
//
// return !(*ring->cq.kflags & IORING_CQ_EVENTFD_DISABLED);
// }
//
// /*
// * Toggle eventfd notification on or off, if an eventfd is registered with
// * the ring.
// */
// IOURINGINLINE int io_uring_cq_eventfd_toggle(struct io_uring *ring,
// bool enabled)
// {
// uint32_t flags;
//
// if (!!enabled == io_uring_cq_eventfd_enabled(ring))
// return 0;
//
// if (!ring->cq.kflags)
// return -EOPNOTSUPP;
//
// flags = *ring->cq.kflags;
//
// if (enabled)
// flags &= ~IORING_CQ_EVENTFD_DISABLED;
// else
// flags |= IORING_CQ_EVENTFD_DISABLED;
//
// IO_URING_WRITE_ONCE(*ring->cq.kflags, flags);
//
// return 0;
// }
//
// /*
// * Return an IO completion, waiting for 'wait_nr' completions if one isn't
// * readily available. Returns 0 with cqe_ptr filled in on success, -errno on
// * failure.
// */
// IOURINGINLINE int io_uring_wait_cqe_nr(struct io_uring *ring,
// struct io_uring_cqe **cqe_ptr,
// unsigned wait_nr)
// {
// return __io_uring_get_cqe(ring, cqe_ptr, 0, wait_nr, NULL);
// }
//
// /*
// * Internal helper, don't use directly in applications. Use one of the
// * "official" versions of this, io_uring_peek_cqe(), io_uring_wait_cqe(),
// * or io_uring_wait_cqes*().
// */
// IOURINGINLINE int __io_uring_peek_cqe(struct io_uring *ring,
// struct io_uring_cqe **cqe_ptr,
// unsigned *nr_available)
// {
// struct io_uring_cqe *cqe;
// int err = 0;
// unsigned available;
// unsigned mask = ring->cq.ring_mask;
// int shift = 0;
//
// if (ring->flags & IORING_SETUP_CQE32)
// shift = 1;
//
// do {
// unsigned tail = io_uring_smp_load_acquire(ring->cq.ktail);
// unsigned head = *ring->cq.khead;
//
// cqe = NULL;
// available = tail - head;
// if (!available)
// break;
//
// cqe = &ring->cq.cqes[(head & mask) << shift];
// if (!(ring->features & IORING_FEAT_EXT_ARG) &&
// cqe->user_data == LIBURING_UDATA_TIMEOUT) {
// if (cqe->res < 0)
// err = cqe->res;
// io_uring_cq_advance(ring, 1);
// if (!err)
// continue;
// cqe = NULL;
// }
//
// break;
// } while (1);
//
// *cqe_ptr = cqe;
// if (nr_available)
// *nr_available = available;
// return err;
// }
//
// /*
// * Return an IO completion, if one is readily available. Returns 0 with
// * cqe_ptr filled in on success, -errno on failure.
// */
// IOURINGINLINE int io_uring_peek_cqe(struct io_uring *ring,
// struct io_uring_cqe **cqe_ptr)
// {
// if (!__io_uring_peek_cqe(ring, cqe_ptr, NULL) && *cqe_ptr)
// return 0;
//
// return io_uring_wait_cqe_nr(ring, cqe_ptr, 0);
// }
//
// /*
// * Return an IO completion, waiting for it if necessary. Returns 0 with
// * cqe_ptr filled in on success, -errno on failure.
// */
// IOURINGINLINE int io_uring_wait_cqe(struct io_uring *ring,
// struct io_uring_cqe **cqe_ptr)
// {
// if (!__io_uring_peek_cqe(ring, cqe_ptr, NULL) && *cqe_ptr)
// return 0;
//
// return io_uring_wait_cqe_nr(ring, cqe_ptr, 1);
// }
//
// /*
// * Return an sqe to fill. Application must later call io_uring_submit()
// * when it's ready to tell the kernel about it. The caller may call this
// * function multiple times before calling io_uring_submit().
// *
// * Returns a vacant sqe, or NULL if we're full.
// */
// IOURINGINLINE struct io_uring_sqe *_io_uring_get_sqe(struct io_uring *ring)
// {
// struct io_uring_sq *sq = &ring->sq;
// unsigned int head, next = sq->sqe_tail + 1;
// int shift = 0;
//
// if (ring->flags & IORING_SETUP_SQE128)
// shift = 1;
// if (!(ring->flags & IORING_SETUP_SQPOLL))
// head = *sq->khead;
// else
// head = io_uring_smp_load_acquire(sq->khead);
//
// if (next - head <= sq->ring_entries) {
// struct io_uring_sqe *sqe;
//
// sqe = &sq->sqes[(sq->sqe_tail & sq->ring_mask) << shift];
// sq->sqe_tail = next;
// io_uring_initialize_sqe(sqe);
// return sqe;
// }
//
// return NULL;
// }
func CqeGetData(cqe *CompletionQueueEvent) (uint64, error) {
	if cqe == nil {
		return 0, errors.New("cqe is nil")
	}

	return cqe.UserData, nil
}
