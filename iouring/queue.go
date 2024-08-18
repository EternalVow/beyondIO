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

// io_uring_prep_readv
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

// io_uring_prep_writev
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

func PrepTimeout(sqe *SubmissionQueueEntry, ts *syscall.Timespec, count uint64, flags int) error {
	err := PrepRw(int(OpTimeout), sqe, -1, unsafe.Pointer(ts), 1, count)
	if err != nil {
		return err
	}

	sqe.TimeoutFlags = uint32(flags)

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

// io_uring_prep_recvmsg_multishot
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

// io_uring_prep_cancel_fd
func PrepCancelFd(sqe *SubmissionQueueEntry, fd int, flags uint) error {
	err := PrepRw(int(OpAsyncCancel), sqe, fd, nil, 0, 0)
	if err != nil {
		return err
	}
	sqe.CancelFlags = uint32(flags) | AsyncCancelFd

	return nil
}

// io_uring_prep_connect
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

// io_uring_prep_close
func PrepClose(sqe *SubmissionQueueEntry, fd int) error {
	err := PrepRw(int(OpClose), sqe, fd, nil, 0, 0)
	if err != nil {
		return err
	}

	return nil
}

// io_uring_prep_close_direct
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

// prep_sendmsg_zc
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

// io_uring_prep_shutdown
func PrepShutdown(sqe *SubmissionQueueEntry, fd int, how int) error {
	err := PrepRw(int(OpShutdown), sqe, fd, nil, uint32(how), 0)
	if err != nil {
		return err
	}
	return nil
}

// io_uring_prep_socket
func PrepSocket(sqe *SubmissionQueueEntry, domain int, stype int, protocol int, flag uint) error {
	err := PrepRw(int(OpSocket), sqe, domain, nil, uint32(protocol), uint64(stype))
	if err != nil {
		return err
	}
	sqe.RwFlags = uint8(flag)
	return nil
}

// io_uring_prep_socket_direct
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

// io_uring_prep_socket_direct_alloc
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

func CqReady(ioUring *Ring) uint32 {

	return atomic.LoadUint32(ioUring.cqRing.tail) - *ioUring.cqRing.head
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
		tail := atomic.LoadUint32(ioUring.cqRing.tail)
		head := *ioUring.cqRing.head

		cqe = nil
		available = uint32(tail - head)
		if available == 0 {
			break
		}

		cqeNewPoiter := uintptr(unsafe.Pointer(ioUring.cqRing.cqes)) + uintptr(((head&mask)<<shift)*unsafe.Sizeof(CompletionQueue{}))
		cqe = (*CompletionQueueEvent)(unsafe.Pointer(cqeNewPoiter))
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
		atomic.StoreUint32(cq.head, *cq.head+nr)
	}
}

// io_uring_cqe_seen
func CqeSeen(ioUring *Ring, cqe *CompletionQueueEvent) {
	if cqe != nil {
		CqAdvance(ioUring, 1)
	}
}

/*
 * Returns true if we're not using SQ thread (thus nobody submits but us)
 * or if IORING_SQ_NEED_WAKEUP is set, so submit thread must be explicitly
 * awakened. For the latter case, we set the thread wakeup flag.
 * If no SQEs are ready for submission, returns false.
 */
// sq_ring_needs_enter
func SqRingNeedsEnter(ioUring *Ring, submit uint, flags *uint32) bool {
	if submit == 0 {
		return false
	}

	if ioUring.flags&SetupSQPoll == 0 {
		return true
	}

	/*
	 * Ensure the kernel can see the store to the SQ tail before we read
	 * the flags.
	 */

	/*	io_uring_smp_mb();

		if (uring_unlikely(IO_URING_READ_ONCE(*ring->sq.kflags) &
			IORING_SQ_NEED_WAKEUP)) {
			*flags |= IORING_ENTER_SQ_WAKEUP;
			return true;
		}*/

	return false
}

func CqRingNeedsFlush(ioUring *Ring) bool {
	return (uint32(atomic.LoadUint32(ioUring.sqRing.flags)) & (SQCQOverflow | SQTaskrun)) != 0
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

		if looped && data.HasTs {
			arg := (*GeteventsArg)(data.Arg)
			if cqe == nil && arg.ts != nil && err == nil {
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
		head = uint32(atomic.LoadUint32(sq.head))

	}

	if next-head <= *sq.ringEntries {
		//struct io_uring_sqe *sqe;

		sqeNewPoiter := uintptr(unsafe.Pointer(sq.sqes)) + uintptr(((sq.sqeTail&*sq.ringMask)<<shift)*unsafe.Sizeof(SubmissionQueueEntry{}))
		sqe := (*SubmissionQueueEntry)(unsafe.Pointer(sqeNewPoiter))

		//sqe := sq.sqes[(sq.sqeTail&*sq.ringMask)<<shift]
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

func GetEvents(ioUring *Ring) (uint, error) {

	var flags = EnterGetevents

	if (ioUring.intFlags & IntFlagRegRing) != 0 {
		flags |= EnterRegisteredRing
	}
	return SyscallIoUringEnter(uint32(ioUring.enterRingFd), 0, 0, flags, nil)
}

/*
 * Fill in an array of IO completions up to count, if any are available.
 * Returns the amount of IO completions filled.
 */
func PeekBatchCqe(ioUring *Ring, cqe_ptr **CompletionQueueEvent, count uint) uint {
	var (
		ready            uint
		overflow_checked bool
		shift            int
	)
	if ioUring.flags&SetupCQE32 != 0 {
		shift = 1
	}

	for {
		ready = uint(CqReady(ioUring))
		if ready != 0 {
			head := *ioUring.cqRing.head
			mask := *ioUring.cqRing.ringMask
			var last uint
			var i int
			if count > ready {
				count -= ready
			}
			last = uint(head) + count

			for uint(head) != last {
				//cqes[i] = &ring->cq.cqes[(head & mask) << shift];
				cqeNewPoiter := uintptr(unsafe.Pointer(ioUring.cqRing.cqes)) + uintptr(((head&mask)<<shift)*unsafe.Sizeof(CompletionQueue{}))
				cqePointer := (*CompletionQueue)(unsafe.Pointer(cqeNewPoiter))

				cqes_i_ptr := (**CompletionQueue)(unsafe.Pointer(uintptr(unsafe.Pointer(cqe_ptr)) + uintptr(uintptr(i)*unsafe.Sizeof(uint32(0)))))
				*cqes_i_ptr = cqePointer

				head++
				i++
			}

			return count
		}

		if overflow_checked {
			return 0
		}

		if CqRingNeedsFlush(ioUring) {
			GetEvents(ioUring)
			overflow_checked = true
			continue
		} else {
			break
		}

	}

	return 0

}

/*
 * Sync internal state with kernel ring state on the SQ side. Returns the
 * number of pending items in the SQ ring, for the shared ring.
 */
func FlushSq(ioUring *Ring) uint {

	sq := ioUring.sqRing
	tail := sq.sqeTail
	if sq.sqeHead != tail {
		sq.sqeHead = tail
	}

	/*
	 * Ensure kernel sees the SQE updates before the tail update.
	 */
	if (ioUring.flags & SetupSQPoll) == 0 {
		*sq.tail = tail
	} else {
		atomic.StoreUint32(sq.tail, tail)
	}

	/*
	* This load needs to be atomic, since sq->khead is written concurrently
	* by the kernel, but it doesn't need to be load_acquire, since the
	* kernel doesn't store to the submission queue; it advances khead just
	* to indicate that it's finished reading the submission queue entries
	* so they're available for us to write to.
	 */
	return uint(tail - atomic.LoadUint32(sq.head))
}

/*
 * If we have kernel support for IORING_ENTER_EXT_ARG, then we can use that
 * more efficiently than queueing an internal timeout command.
 */

func WaitCqesNew(ioUring *Ring, cqe_ptr **CompletionQueueEvent, wait_nr uint, ts *syscall.Timespec, sigmask *unix.Sigset_t) error {

	arg := GeteventsArg{
		sigmask:    *sigmask,
		sigmask_sz: nSig / 8,
		ts:         ts,
	}

	data := GetData{
		WaitNr:   uint64(wait_nr),
		GetFlags: uint64(EnterExtArg),
		Sz:       int(unsafe.Sizeof(arg)),
		HasTs:    ts != nil,
		Arg:      unsafe.Pointer(&arg),
	}

	return getCqe(ioUring, cqe_ptr, &data)

}

/*
 * Submit sqes acquired from io_uring_get_sqe() to the kernel.
 *
 * Returns number of sqes submitted
 */
//__io_uring_submit
func submit(ioUring *Ring, submitted uint, wait_nr uint, getevents bool) (uint, error) {

	cq_needs_enter := getevents || (wait_nr > 0) || CqRingNeedsEnter(ioUring)
	var flags uint32
	var ret uint
	var err error

	if SqRingNeedsEnter(ioUring, submitted, &flags) || cq_needs_enter {
		if cq_needs_enter {
			flags |= EnterGetevents
		}

		if ioUring.intFlags&IntFlagRegRing != 0 {
			flags |= EnterRegisteredRing
		}

		ret, err = SyscallIoUringEnter(uint32(ioUring.enterRingFd), uint32(submitted), uint32(wait_nr), flags, nil)
		if err != nil {
			return 0, err
		}

	} else {
		return submitted, nil
	}
	return ret, nil
}

// __io_uring_submit_and_wait
func SubmitAndWait(ioUring *Ring, wait_nr uint) (uint, error) {
	return submit(ioUring, FlushSq(ioUring), wait_nr, false)
}

func Submit(ioUring *Ring) (uint, error) {
	return SubmitAndWait(ioUring, 0)
}

/*
 * Like io_uring_wait_cqe(), except it accepts a timeout value as well. Note
 * that an sqe is used internally to handle the timeout. For kernel doesn't
 * support IORING_FEAT_EXT_ARG, applications using this function must never
 * set sqe->user_data to LIBURING_UDATA_TIMEOUT!
 *
 * For kernels without IORING_FEAT_EXT_ARG (5.10 and older), if 'ts' is
 * specified, the application need not call io_uring_submit() before
 * calling this function, as we will do that on its behalf. From this it also
 * follows that this function isn't safe to use for applications that split SQ
 * and CQ handling between two threads and expect that to work without
 * synchronization, as this function manipulates both the SQ and CQ side.
 *
 * For kernels with IORING_FEAT_EXT_ARG, no implicit submission is done and
 * hence this function is safe to use for applications that split SQ and CQ
 * handling between two threads.
 */
func SubmitTimeout(ioUring *Ring, wait_nr uint, ts *syscall.Timespec) (uint, error) {

	var ret uint
	var err error

	sqe := GetSqe(ioUring)
	if sqe == nil {
		ret, err = Submit(ioUring)
		if err != nil {
			return 0, err
		}
	}
	if ret < 0 {
		return ret, nil
	}
	sqe = GetSqe(ioUring)
	if sqe == nil {
		return 0, errors.New("EAGAIN")
	}

	PrepTimeout(sqe, ts, uint64(wait_nr), 0)
	sqe.UserData = LiburingUdataTimeout

	return FlushSq(ioUring), nil

}

// io_uring_wait_cqe
func WaitCqes(ioUring *Ring, cqe_ptr **CompletionQueueEvent, wait_nr uint, ts *syscall.Timespec, sigmask *unix.Sigset_t) (uint, error) {
	var toSubmit uint
	var err error
	if ts != nil {
		if ioUring.features&FeatExtArg > 0 {
			return 0, WaitCqesNew(ioUring, cqe_ptr, wait_nr, ts, sigmask)
		}
		toSubmit, err = SubmitTimeout(ioUring, wait_nr, ts)
		if toSubmit < 0 {
			return toSubmit, err
		}

	}

	return 0, GetCqe(ioUring, cqe_ptr, uint64(toSubmit), uint64(wait_nr), sigmask)
}

/*
 * See io_uring_wait_cqes() - this function is the same, it just always uses
 * '1' as the wait_nr.
 */
func WaitCqesTimeout(ioUring *Ring, cqe_ptr **CompletionQueueEvent, wait_nr uint, ts *syscall.Timespec) (uint, error) {
	return WaitCqes(ioUring, cqe_ptr, 1, ts, nil)
}

// io_uring_submit_and_get_events
func SubmitAndGetEvents(ioUring *Ring) (uint, error) {
	return submit(ioUring, FlushSq(ioUring), 0, true)
}

// __io_uring_sqring_wait
func SqringWait(ioUring *Ring) (uint, error) {
	flags := EnterSQWait
	if (ioUring.flags & IntFlagRegRing) == 0 {
		flags |= EnterRegisteredRing
	}
	return SyscallIoUringEnter(uint32(ioUring.enterRingFd), 0, 0, flags, nil)
}

// io_uring_queue_exit
func QueueExit(ioUring *Ring) {
	sq := ioUring.sqRing
	cq := ioUring.cqRing
	var sqe_size uint64

	if sq.ringSize == 0 {
		sqe_size = uint64(unsafe.Sizeof(SubmissionQueueEntry{}))
		if ioUring.flags&SetupSQE128 != 0 {
			sqe_size += 64
		}
		munmap(uintptr(unsafe.Pointer(sq.sqes)), uintptr(sqe_size*uint64(*sq.ringEntries)))
		UnmapRings(sq, cq)
	} else {
		if ioUring.flags&IntFlagAppMem == 0 {
			munmap(uintptr(unsafe.Pointer(sq.sqes)), uintptr(*sq.ringEntries)*unsafe.Sizeof(SubmissionQueueEntry{}))
			UnmapRings(sq, cq)
		}
	}

	/*
	 * Not strictly required, but frees up the slot we used now rather
	 * than at process exit time.
	 */
	if (ioUring.intFlags & IntFlagRegRing) != 0 {
		DoUnregisterRingFd(ioUring)
	}

	if ioUring.ringFd != -1 {
		syscall.Close(ioUring.ringFd)
	}
}
