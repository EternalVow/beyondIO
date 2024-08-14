package iouring

import (
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"sync/atomic"
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

func InitializeSqe(sqe *SubmissionQueueEntry) {
	sqe.Flags = 0
	sqe.IoPrio = 0
	sqe.RwFlags = 0
	sqe.BufIndex = 0
	sqe.Personality = 0
	sqe.FileIndex = 0
	sqe.Addr3 = 0
	sqe._pad2[0] = 0

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

func PrepEpollCtl(sqe *SubmissionQueueEntry, epfd int, fd int, op int, ev *syscall.EpollEvent) error {
	err := PrepRw(int(OpEpollCtl), sqe, epfd, unsafe.Pointer(ev), uint32(op), uint64(fd))
	if err != nil {
		return err
	}

	return nil
}

func PrepProvideBuffers(sqe *SubmissionQueueEntry, addr *syscall.Sockaddr, len int, nr int, bgid int, bid int) error {
	err := PrepRw(int(OpProvideBuffers), sqe, nr, unsafe.Pointer(addr), uint32(len), uint64(bid))
	if err != nil {
		return err
	}
	sqe.BufGroup = uint64(bgid)
	return nil
}

func PrepRemoveBuffers(sqe *SubmissionQueueEntry, nr int, bgid int) error {
	err := PrepRw(int(OpRemoveBuffers), sqe, nr, nil, 0, 0)
	if err != nil {
		return err
	}
	sqe.BufGroup = uint64(bgid)
	return nil
}

func PrepShutdown(sqe *SubmissionQueueEntry, fd int, how int) error {
	err := PrepRw(int(OpShutdown), sqe, fd, nil, uint32(how), 0)
	if err != nil {
		return err
	}
	return nil
}

func PrepSocket(sqe *SubmissionQueueEntry, domain int, stype int, protocol int, flag uint) error {
	err := PrepRw(int(OpSocket), sqe, domain, nil, uint32(protocol), uint64(stype))
	if err != nil {
		return err
	}
	sqe.RwFlags = uint8(flag)
	return nil
}

func PrepSocketDirect(sqe *SubmissionQueueEntry, domain int, stype int, protocol int, file_index uint32, flag uint) error {
	err := PrepRw(int(OpSocket), sqe, domain, nil, uint32(protocol), uint64(stype))
	if err != nil {
		return err
	}
	sqe.RwFlags = uint8(flag)
	/* offset by 1 for allocation */
	if file_index == FileIndexAlloc {
		file_index--
		SetTarGetFixedFile(sqe, file_index)
	}
	return nil
}

func PrepSocketDirectAlloc(sqe *SubmissionQueueEntry, domain int, stype int, protocol int, flag uint) error {
	err := PrepRw(int(OpSocket), sqe, domain, nil, uint32(protocol), uint64(stype))
	if err != nil {
		return err
	}
	sqe.RwFlags = uint8(flag)
	/* offset by 1 for allocation */
	SetTarGetFixedFile(sqe, FileIndexAlloc-1)

	return nil
}

func PrepCqReady(ioUring *Ring) int32 {

	return atomic.LoadInt32(ioUring.cqRing.tail) - *ioUring.cqRing.head
}

//func WaitCqeNr(ioUring *Ring, cqe_ptr **CompletionQueueEvent, wait_nr uint) bool {
//
//}

// __io_uring_peek_cqe
func peekCqe(ioUring *Ring, cqe_ptr **CompletionQueueEvent, nr_available *uint32) error {
	var (
		cqe       *CompletionQueueEvent
		err       error
		available uint32
		mask      = *ioUring.cqRing.ringMask
		shift     int
	)
	if ioUring.flags&SetupCQE32 != 0 {
		shift = 1
	}
	for {
		tail := atomic.LoadInt32(ioUring.cqRing.tail)
		head := *ioUring.cqRing.head

		cqe = nil
		available = uint32(tail - head)
		if available == 0 {
			break
		}
		cqe = ioUring.cqRing.cqes[(uint32(head)&mask)<<shift]
		if ioUring.features&FeatExtArg == 0 && cqe.UserData == LiburingUdataTimeout {
			if cqe.Res < 0 {
				err = fmt.Errorf("cqe.Res err = %v", err)
			}
			CqAdvance(ioUring, 1)
			if err == nil {
				continue
			}
			cqe = nil

		}

		break
	}
	*cqe_ptr = cqe
	if nr_available != nil {
		*nr_available = available
	}
	return err
}

// io_uring_cq_advance
func CqAdvance(ioUring *Ring, nr uint32) {
	if nr != 0 {
		cq := ioUring.cqRing

		/*
		 * Ensure that the kernel only sees the new value of the head
		 * index after the CQEs have been read.
		 */
		atomic.StoreInt32(cq.head, *cq.head+int32(nr))
	}
}

func CqRingNeedsFlush(ioUring *Ring) bool {
	return (uint32(atomic.LoadInt32(ioUring.sqRing.flags)) & (SQCQOverflow | SQTaskrun)) != 0
}

// cq_ring_needs_enter
func CqRingNeedsEnter(ioUring *Ring) bool {
	return (ioUring.flags&SetupIOPoll) != 0 || CqRingNeedsFlush(ioUring)
}

// _io_uring_get_cqe
func getCqe(ioUring *Ring, cqe_ptr **CompletionQueueEvent, data *GetData) error {
	var (
		cqe    *CompletionQueueEvent
		looped bool
		err    error
	)

	for {
		var (
			needEnter   bool
			flags       uint32
			nrAvailable uint32
			errRet      error
		)
		errRet = peekCqe(ioUring, &cqe, &nrAvailable)
		if errRet != nil {
			err = errRet
			break
		}

		if cqe == nil && data.WaitNr == 0 && data.Submit == 0 {
			/*
			 * If we already looped once, we already entered
			 * the kernel. Since there's nothing to submit or
			 * wait for, don't keep retrying.
			 */
			if looped || (!CqRingNeedsEnter(ioUring)) {
				if err == nil {
					err = fmt.Errorf("-EAGAIN")
				}
				break
			}
			needEnter = true
		}
		if data.WaitNr > uint64(nrAvailable) || needEnter {
			flags = EnterGetevents | uint32(data.GetFlags)
			needEnter = true
		}
		if !needEnter {
			break
		}

		if looped && data.HasTs != 0 {
			arg := (*GeteventsArg)(data.Arg)
			if cqe == nil && arg.ts != 0 && err == nil {
				err = fmt.Errorf("-EAGAIN")
				break
			}
		}

		if (ioUring.intFlags & IntFlagRegRing) != 0 {
			flags |= EnterRegisteredRing
		}
		consumed, errno := SyscallIoUringEnter2(uint32(ioUring.enterRingFd), uint32(data.Submit), uint32(data.WaitNr), flags, data.Arg, data.Sz)
		if errno != nil {
			if err == nil {
				err = errno
			}
			break
		}

		data.Submit -= uint64(consumed)
		if cqe != nil {
			break
		}
		if !looped {
			looped = true
			err = errRet
		}
	}
	*cqe_ptr = cqe
	return err
}

// __io_uring_get_cqe
func GetCqe(ioUring *Ring, cqe_ptr **CompletionQueueEvent, submit uint64, wait_nr uint64, sigmask *unix.Sigset_t) error {
	data := GetData{
		Submit:   submit,
		WaitNr:   wait_nr,
		GetFlags: 0,
		Sz:       nSig / szDivider,
		Arg:      unsafe.Pointer(sigmask),
	}
	return getCqe(ioUring, cqe_ptr, &data)
}

// /*
// * Return an IO completion, waiting for 'wait_nr' completions if one isn't
// * readily available. Returns 0 with cqe_ptr filled in on success, -errno on
// * failure.
// */
func WaitCqeNr(ioUring *Ring, cqe_ptr **CompletionQueueEvent, wait_nr uint64) error {

	return GetCqe(ioUring, cqe_ptr, 0, wait_nr, nil)
}

// /*
// * Return an IO completion, if one is readily available. Returns 0 with
// * cqe_ptr filled in on success, -errno on failure.
// */
func PeekCqe(ioUring *Ring, cqe_ptr **CompletionQueueEvent) error {

	if err := peekCqe(ioUring, cqe_ptr, nil); err == nil {
		if *cqe_ptr != nil {
			return nil
		}
	}
	return WaitCqeNr(ioUring, cqe_ptr, 0)
}

// /*
// * Return an IO completion, waiting for it if necessary. Returns 0 with
// * cqe_ptr filled in on success, -errno on failure.
// */
func WaitCqe(ioUring *Ring, cqe_ptr **CompletionQueueEvent) error {

	if err := peekCqe(ioUring, cqe_ptr, nil); err == nil {
		if *cqe_ptr != nil {
			return nil
		}
	}
	return WaitCqeNr(ioUring, cqe_ptr, 1)
}

// /*
// * Return an sqe to fill. Application must later call io_uring_submit()
// * when it's ready to tell the kernel about it. The caller may call this
// * function multiple times before calling io_uring_submit().
// *
// * Returns a vacant sqe, or NULL if we're full.
// */
// _io_uring_get_sqe
func GetSqe(ioUring *Ring) *SubmissionQueueEntry {
	sq := ioUring.sqRing

	head := sq.sqeTail + 1
	next := head
	var shift int

	if (ioUring.flags & SetupSQE128) != 0 {
		shift = 1
	}
	if (ioUring.flags & SetupSQPoll) == 0 {
		head = uint32(*sq.head)
	} else {
		head = uint32(atomic.LoadInt32(sq.head))

	}

	if next-head <= *sq.ringEntries {
		//struct io_uring_sqe *sqe;

		sqe := sq.sqes[(sq.sqeTail&*sq.ringMask)<<shift]
		sq.sqeTail = next
		InitializeSqe(sqe)
		return sqe
	}

	return nil
}

func CqeGetData(cqe *CompletionQueueEvent) (uint64, error) {
	if cqe == nil {
		return 0, errors.New("cqe is nil")
	}

	return cqe.UserData, nil
}
