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

func PrepReadv(sqe *SubmissionQueueEntry, fd int, iovec *syscall.Iovec, nr_vecs uint, offset uint64) error {
	err := PrepRw(int(OpReadv), sqe, fd, unsafe.Pointer(iovec), uint32(nr_vecs), 0)
	if err != nil {
		return err
	}

	return nil
}

func PrepReadv2(sqe *SubmissionQueueEntry, fd int, iovec *syscall.Iovec, nr_vecs uint, offset uint64, flags int) error {
	err := PrepReadv(sqe, fd, iovec, nr_vecs, offset)
	if err != nil {
		return err
	}
	sqe.RwFlags = uint8(flags)

	return nil
}

//
//
//IOURINGINLINE void io_uring_prep_read_fixed(struct io_uring_sqe *sqe, int fd,
//void *buf, unsigned nbytes,
//__u64 offset, int buf_index)
//{
//io_uring_prep_rw(IORING_OP_READ_FIXED, sqe, fd, buf, nbytes, offset);
//sqe->buf_index = (__u16) buf_index;
//}
//
//IOURINGINLINE void io_uring_prep_writev(struct io_uring_sqe *sqe, int fd,
//const struct iovec *iovecs,
//unsigned nr_vecs, __u64 offset)
//{
//io_uring_prep_rw(IORING_OP_WRITEV, sqe, fd, iovecs, nr_vecs, offset);
//}
//
//IOURINGINLINE void io_uring_prep_writev2(struct io_uring_sqe *sqe, int fd,
//const struct iovec *iovecs,
//unsigned nr_vecs, __u64 offset,
//int flags)
//{
//io_uring_prep_writev(sqe, fd, iovecs, nr_vecs, offset);
//sqe->rw_flags = flags;
//}
//
//IOURINGINLINE void io_uring_prep_write_fixed(struct io_uring_sqe *sqe, int fd,
//const void *buf, unsigned nbytes,
//__u64 offset, int buf_index)
//{
//io_uring_prep_rw(IORING_OP_WRITE_FIXED, sqe, fd, buf, nbytes, offset);
//sqe->buf_index = (__u16) buf_index;
//}
//
//IOURINGINLINE void io_uring_prep_recvmsg(struct io_uring_sqe *sqe, int fd,
//struct msghdr *msg, unsigned flags)
//{
//io_uring_prep_rw(IORING_OP_RECVMSG, sqe, fd, msg, 1, 0);
//sqe->msg_flags = flags;
//}
//
//IOURINGINLINE void io_uring_prep_recvmsg_multishot(struct io_uring_sqe *sqe,
//int fd, struct msghdr *msg,
//unsigned flags)
//{
//io_uring_prep_recvmsg(sqe, fd, msg, flags);
//sqe->ioprio |= IORING_RECV_MULTISHOT;
//}
//
//IOURINGINLINE void io_uring_prep_sendmsg(struct io_uring_sqe *sqe, int fd,
//const struct msghdr *msg,
//unsigned flags)
//{
//io_uring_prep_rw(IORING_OP_SENDMSG, sqe, fd, msg, 1, 0);
//sqe->msg_flags = flags;
//}

func CqeGetData(cqe *CompletionQueueEvent) (uint64, error) {
	if cqe == nil {
		return 0, errors.New("cqe is nil")
	}

	return cqe.UserData, nil
}
