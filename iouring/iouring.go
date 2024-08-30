package iouring

import (
	"errors"
	"golang.org/x/sys/unix"
	"syscall"
	"unsafe"
)

type IIouring interface {
	QueueInitParams(entries uint, ioUring *Ring, p *Params) error
	QueueInit(entries uint, ioUring *Ring, flags uint32) error
	QueueInitMem(entries uint, ioUring *Ring, p *Params, buf unsafe.Pointer, bufSize uint) error
	QueueInitTryNosqarr(entries uint, ioUring *Ring, p *Params, buf unsafe.Pointer, bufSize uint) error

	GetSqe(ioUring *Ring) *SubmissionQueueEntry
	SqeSetData(sqe *SubmissionQueueEntry, data uint64) error
	PrepReadv(sqe *SubmissionQueueEntry, fd int, iovec *syscall.Iovec, nr_vecs uint32, offset uint64) error
	PrepReadv2(sqe *SubmissionQueueEntry, fd int, iovec *syscall.Iovec, nr_vecs uint32, offset uint64, flags int) error
	PrepReadWritev(sqe *SubmissionQueueEntry, fd int, iovec *syscall.Iovec, nr_vecs uint32, offset uint64) error
	PrepReadWritev2(sqe *SubmissionQueueEntry, fd int, iovec *syscall.Iovec, nr_vecs uint32, offset uint64, flags int) error
	WaitCqes(ioUring *Ring, cqe_ptr **CompletionQueueEvent, wait_nr uint, ts *syscall.Timespec, sigmask *unix.Sigset_t) (uint, error)
	PeekCqe(ioUring *Ring, cqe_ptr **CompletionQueueEvent) error
	CqeGetData(cqe *CompletionQueueEvent) (uint64, error)
	CqeSeen(ioUring *Ring, cqe *CompletionQueueEvent)
	QueueExit(ioUring *Ring)
	PrepRecvmsg(sqe *SubmissionQueueEntry, fd int, msgh *syscall.Msghdr, flags int) error
	PrepRecvmsgMultishot(sqe *SubmissionQueueEntry, fd int, msgh *syscall.Msghdr, flags int) error
	PrepSendmsg(sqe *SubmissionQueueEntry, fd int, msgh *syscall.Msghdr, flags int) error
	PrepAccept(sqe *SubmissionQueueEntry, fd int, addr *syscall.Sockaddr, addrlen uint64, flags int) error
	PrepAcceptDirect(sqe *SubmissionQueueEntry, fd int, addr *syscall.Sockaddr, addrlen uint64, flags int, file_index uint32) error
	PrepMultishotAccept(sqe *SubmissionQueueEntry, fd int, addr *syscall.Sockaddr, addrlen uint64, flags int) error
	PrepMultishotAcceptDirect(sqe *SubmissionQueueEntry, fd int, addr *syscall.Sockaddr, addrlen uint64, flags int) error
	CqAdvance(ioUring *Ring, nr uint32)
	SqringWait(ioUring *Ring) (uint, error)
	PrepShutdown(sqe *SubmissionQueueEntry, fd int, how int) error
	PrepClose(sqe *SubmissionQueueEntry, fd int) error
	PrepCloseDirect(sqe *SubmissionQueueEntry, file_index uint32) error
	PrepCancelFd(sqe *SubmissionQueueEntry, fd int, flags uint) error
	PrepCancel64(sqe *SubmissionQueueEntry, user_data uint64, flags int) error
	PrepConnect(sqe *SubmissionQueueEntry, fd int, addr *syscall.Sockaddr, addrlen uint64) error
	PrepBind(sqe *SubmissionQueueEntry, fd int, addr *syscall.Sockaddr, addrlen uint64) error
	PrepListen(sqe *SubmissionQueueEntry, fd int, backlog uint32) error
	PrepSendmsgZc(sqe *SubmissionQueueEntry, fd int, msgh *syscall.Msghdr, flags int) error
	PrepSocket(sqe *SubmissionQueueEntry, domain int, stype int, protocol int, flag uint) error
	PrepSocketDirect(sqe *SubmissionQueueEntry, domain int, stype int, protocol int, file_index uint32, flag uint) error
	PrepSocketDirectAlloc(sqe *SubmissionQueueEntry, domain int, stype int, protocol int, flag uint) error
	SubmitTimeout(ioUring *Ring, wait_nr uint, ts *syscall.Timespec) (uint, error)
	SubmitAndWait(ioUring *Ring, wait_nr uint) (uint, error)
	Submit(ioUring *Ring) (uint, error)

	DoRegisterFiles(ioUring *Ring, files *int, nr_files uint)
	DoRegisterRingFd(ioUring *Ring) (uint, error)
	DoRegisterBuffers(ioUring *Ring, iovecs *syscall.Iovec, nr_iovecs uint) (uint, error)
	DoUnRegisterBuffers(ioUring *Ring) (uint, error)
	DoUnregisterFiles(ioUring *Ring) (uint, error)
	DoRegisterEventfd(ioUring *Ring, event_fd int) (uint, error)
	DoUnregisterEventfd(ioUring *Ring, event_fd int) (uint, error)
}

func InitIouring() (*Iouring, error) {
	return &Iouring{
		Ring: &Ring{},
	}, nil
}

type Iouring struct {
	Ring *Ring
}

func (i Iouring) GetSqe(ioUring *Ring) *SubmissionQueueEntry {
	return GetSqe(ioUring)
}

func (i Iouring) SqeSetData(sqe *SubmissionQueueEntry, data uint64) error {
	return SqeSetData(sqe, data)

}

func (i Iouring) PrepRead(sqe *SubmissionQueueEntry, fd int, buf unsafe.Pointer, nbytes uint32, offset uint64) error {
	return PrepRead(sqe, fd, buf, nbytes, offset)
}

func (i Iouring) PrepReadv(sqe *SubmissionQueueEntry, fd int, iovec *syscall.Iovec, nr_vecs uint32, offset uint64) error {
	return PrepReadv(sqe, fd, iovec, nr_vecs, offset)
}

func (i Iouring) PrepReadv2(sqe *SubmissionQueueEntry, fd int, iovec *syscall.Iovec, nr_vecs uint32, offset uint64, flags int) error {
	return PrepReadv2(sqe, fd, iovec, nr_vecs, offset, flags)
}

func (i Iouring) PrepWrite(sqe *SubmissionQueueEntry, fd int, buf unsafe.Pointer, nbytes uint32, offset uint64) error {
	return PrepWrite(sqe, fd, buf, nbytes, offset)
}

func (i Iouring) PrepWritev(sqe *SubmissionQueueEntry, fd int, iovec *syscall.Iovec, nr_vecs uint32, offset uint64) error {
	return PrepWritev(sqe, fd, iovec, nr_vecs, offset)
}

func (i Iouring) PrepWritev2(sqe *SubmissionQueueEntry, fd int, iovec *syscall.Iovec, nr_vecs uint32, offset uint64, flags int) error {
	return PrepWritev2(sqe, fd, iovec, nr_vecs, offset, flags)
}

func (i Iouring) WaitCqes(ioUring *Ring, cqe_ptr **CompletionQueueEvent, wait_nr uint, ts *syscall.Timespec, sigmask *unix.Sigset_t) (uint, error) {
	return WaitCqes(ioUring, cqe_ptr, wait_nr, ts, sigmask)
}

func (i Iouring) WaitCqe(ioUring *Ring, cqe_ptr **CompletionQueueEvent) (uint, error) {
	return WaitCqes(ioUring, cqe_ptr, 0, nil, nil)
}

func (i Iouring) PeekCqe(ioUring *Ring, cqe_ptr **CompletionQueueEvent) error {
	return PeekCqe(ioUring, cqe_ptr)
}

func (i Iouring) CqeGetData(cqe *CompletionQueueEvent) (uint64, error) {
	return CqeGetData(cqe)
}

func (i Iouring) CqeSeen(ioUring *Ring, cqe *CompletionQueueEvent) {
	CqeSeen(ioUring, cqe)
}

func (i Iouring) QueueExit(ioUring *Ring) {
	QueueExit(ioUring)
}

func (i Iouring) PrepRecvmsg(sqe *SubmissionQueueEntry, fd int, msgh *syscall.Msghdr, flags int) error {
	return PrepRecvmsg(sqe, fd, msgh, flags)
}

func (i Iouring) PrepRecvmsgMultishot(sqe *SubmissionQueueEntry, fd int, msgh *syscall.Msghdr, flags int) error {
	return PrepRecvmsgMultishot(sqe, fd, msgh, flags)
}

func (i Iouring) PrepSendmsg(sqe *SubmissionQueueEntry, fd int, msgh *syscall.Msghdr, flags int) error {
	return PrepSendmsg(sqe, fd, msgh, flags)
}

func (i Iouring) PrepAccept(sqe *SubmissionQueueEntry, fd int, addr *syscall.Sockaddr, addrlen uint64, flags int) error {
	return PrepAccept(sqe, fd, addr, addrlen, flags)
}

func (i Iouring) PrepAcceptDirect(sqe *SubmissionQueueEntry, fd int, addr *syscall.Sockaddr, addrlen uint64, flags int, file_index uint32) error {
	return PrepAcceptDirect(sqe, fd, addr, addrlen, flags, file_index)
}

func (i Iouring) PrepMultishotAccept(sqe *SubmissionQueueEntry, fd int, addr *syscall.Sockaddr, addrlen uint64, flags int) error {
	return PrepMultishotAccept(sqe, fd, addr, addrlen, flags)
}

func (i Iouring) PrepMultishotAcceptDirect(sqe *SubmissionQueueEntry, fd int, addr *syscall.Sockaddr, addrlen uint64, flags int) error {
	return PrepMultishotAcceptDirect(sqe, fd, addr, addrlen, flags)
}

func (i Iouring) CqAdvance(ioUring *Ring, nr uint32) {
	CqAdvance(ioUring, nr)
}

func (i Iouring) SqringWait(ioUring *Ring) (uint, error) {
	return SqringWait(ioUring)
}

func (i Iouring) PrepShutdown(sqe *SubmissionQueueEntry, fd int, how int) error {
	return PrepShutdown(sqe, fd, how)
}

func (i Iouring) PrepClose(sqe *SubmissionQueueEntry, fd int) error {
	return PrepClose(sqe, fd)
}

func (i Iouring) PrepCloseDirect(sqe *SubmissionQueueEntry, file_index uint32) error {
	return PrepCloseDirect(sqe, file_index)
}

func (i Iouring) PrepCancelFd(sqe *SubmissionQueueEntry, fd int, flags uint) error {
	return PrepCancelFd(sqe, fd, flags)
}

func (i Iouring) PrepCancel64(sqe *SubmissionQueueEntry, user_data uint64, flags int) error {
	return PrepCancel64(sqe, user_data, flags)
}

func (i Iouring) PrepConnect(sqe *SubmissionQueueEntry, fd int, addr *syscall.Sockaddr, addrlen uint64) error {
	return PrepConnect(sqe, fd, addr, addrlen)
}

func (i Iouring) PrepBind(sqe *SubmissionQueueEntry, fd int, addr *syscall.Sockaddr, addrlen uint64) error {
	return PrepBind(sqe, fd, addr, addrlen)
}

func (i Iouring) PrepListen(sqe *SubmissionQueueEntry, fd int, backlog uint32) error {
	return PrepListen(sqe, fd, backlog)
}

func (i Iouring) PrepEpollCtl(sqe *SubmissionQueueEntry, epfd int, fd int, op int, ev *syscall.EpollEvent) error {
	return PrepEpollCtl(sqe, epfd, fd, op, ev)
}

func (i Iouring) PrepSendmsgZc(sqe *SubmissionQueueEntry, fd int, msgh *syscall.Msghdr, flags int) error {
	return PrepSendmsgZc(sqe, fd, msgh, flags)
}

func (i Iouring) PrepSocket(sqe *SubmissionQueueEntry, domain int, stype int, protocol int, flag uint) error {
	return PrepSocket(sqe, domain, stype, protocol, flag)
}

func (i Iouring) PrepSocketDirect(sqe *SubmissionQueueEntry, domain int, stype int, protocol int, file_index uint32, flag uint) error {
	return PrepSocketDirect(sqe, domain, stype, protocol, file_index, flag)
}

func (i Iouring) PrepSocketDirectAlloc(sqe *SubmissionQueueEntry, domain int, stype int, protocol int, flag uint) error {
	return PrepSocketDirectAlloc(sqe, domain, stype, protocol, flag)
}

func (i Iouring) SubmitTimeout(ioUring *Ring, wait_nr uint, ts *syscall.Timespec) (uint, error) {
	return SubmitTimeout(ioUring, wait_nr, ts)
}

func (i Iouring) SubmitAndWait(ioUring *Ring, wait_nr uint) (uint, error) {
	return SubmitAndWait(ioUring, wait_nr)
}

func (i Iouring) Submit(ioUring *Ring) (uint, error) {
	return Submit(ioUring)
}

func (i Iouring) DoRegisterFiles(ioUring *Ring, files *int, nr_files uint) {
	DoRegisterFiles(ioUring, files, nr_files)
}

func (i Iouring) DoRegisterRingFd(ioUring *Ring) (uint, error) {
	return DoRegisterRingFd(ioUring)
}

func (i Iouring) DoRegisterBuffers(ioUring *Ring, iovecs *syscall.Iovec, nr_iovecs uint) (uint, error) {
	return DoRegisterBuffers(ioUring, iovecs, nr_iovecs)
}

func (i Iouring) DoUnRegisterBuffers(ioUring *Ring) (uint, error) {
	return DoUnRegisterBuffers(ioUring)
}

func (i Iouring) DoUnregisterFiles(ioUring *Ring) (uint, error) {
	return DoUnregisterFiles(ioUring)
}

func (i Iouring) DoRegisterEventfd(ioUring *Ring, event_fd int) (uint, error) {
	return DoRegisterEventfd(ioUring, event_fd)
}

func (i Iouring) DoUnregisterEventfd(ioUring *Ring, event_fd int) (uint, error) {
	return DoUnregisterEventfd(ioUring, event_fd)
}

func (i Iouring) QueueInitParams(entries uint, ioUring *Ring, p *Params) error {
	ret, err := QueueInitParams(entries, ioUring, p, nil, 0)
	if ret != 0 || err != nil {
		return errors.New("Failed to initialize Iouring queue")
	}
	return nil
}

func (i Iouring) QueueInitTryNosqarr(entries uint, ioUring *Ring, p *Params, buf unsafe.Pointer, bufSize uint) error {
	var flags = p.Flags

	p.Flags |= SetupNoSQArray
	ret, err := QueueInitParams(entries, ioUring, p, buf, bufSize)

	/* don't fallback if explicitly asked for NOSQARRAY */
	if err != unix.EINVAL || (flags&SetupNoSQArray) == 0 {
		//return ret, nil
		return errors.New("QueueInitParams Failed to initialize Iouring queue")
	}

	p.Flags = flags
	ret, err = QueueInitParams(entries, ioUring, p, buf, bufSize)
	if ret != 0 || err != nil {
		return errors.New("Failed to initialize Iouring queue")
	}
	return nil
}

func (i Iouring) QueueInitMem(entries uint, ioUring *Ring, p *Params, buf unsafe.Pointer, bufSize uint) error {
	p.Flags |= SetupNoMmap
	return i.QueueInitTryNosqarr(entries, ioUring, p, buf, bufSize)
}

func (i Iouring) QueueInit(entries uint, ioUring *Ring, flags uint32) error {
	p := &Params{
		Flags: flags,
	}
	return i.QueueInitParams(entries, ioUring, p)
}
