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

func CqeGetData(cqe *CompletionQueueEvent) (uint64, error) {
	if cqe == nil {
		return 0, errors.New("cqe is nil")
	}

	return cqe.UserData, nil
}
