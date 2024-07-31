package iouring

import (
	"runtime"
	"syscall"
	"unsafe"
)

func (ring *Ring) Enter(submitted uint32, waitNr uint32, flags uint32, sig unsafe.Pointer) (uint, error) {
	return ring.Enter2(submitted, waitNr, flags, sig, nSig/szDivider)
}

func (ring *Ring) Enter2(
	submitted uint32,
	waitNr uint32,
	flags uint32,
	sig unsafe.Pointer,
	size int,
) (uint, error) {
	var (
		consumed uintptr
		errno    syscall.Errno
	)

	consumed, _, errno = syscall.Syscall6(
		sysEnter,
		uintptr(ring.enterRingFd),
		uintptr(submitted),
		uintptr(waitNr),
		uintptr(flags),
		uintptr(sig),
		uintptr(size),
	)

	if errno > 0 {
		return 0, errno
	}

	return uint(consumed), nil
}

// liburing: io_uring_setup - https://manpages.debian.org/unstable/liburing-dev/io_uring_setup.2.en.html
func Setup(entries uint32, p *Params) (uint, error) {
	fd, _, errno := syscall.Syscall(sysSetup, uintptr(entries), uintptr(unsafe.Pointer(p)), 0)
	runtime.KeepAlive(p)

	return uint(fd), errno
}

func syscallRegister(fd int, opcode uint32, arg unsafe.Pointer, nrArgs uint32) (uint, syscall.Errno) {
	returnFirst, _, errno := syscall.Syscall6(
		sysRegister,
		uintptr(fd),
		uintptr(opcode),
		uintptr(arg),
		uintptr(nrArgs),
		0,
		0,
	)

	return uint(returnFirst), errno
}

// liburing: io_uring_register - https://manpages.debian.org/unstable/liburing-dev/io_uring_register.2.en.html
func (ring *Ring) Register(fd int, opcode uint32, arg unsafe.Pointer, nrArgs uint32) (uint, syscall.Errno) {
	return syscallRegister(fd, opcode, arg, nrArgs)
}
