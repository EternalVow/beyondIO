package iouring

import (
	"runtime"
	"syscall"
	"unsafe"
)

func IoUringEnter(fd uint32, submitted uint32, waitNr uint32, flags uint32, sig unsafe.Pointer) (uint, error) {
	return SyscallIoUringEnter2(fd, submitted, waitNr, flags, sig, nSig/szDivider)
}

func SyscallIoUringEnter2(
	fd uint32,
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
		uintptr(fd),
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

func SyscallIoUringSetup(entries uint32, p *Params) (uint, error) {
	fd, _, errno := syscall.Syscall(sysSetup, uintptr(entries), uintptr(unsafe.Pointer(p)), 0)
	runtime.KeepAlive(p)

	return uint(fd), errno
}

func SyscallIoUringRegister(fd int, opcode uint32, arg unsafe.Pointer, nrArgs uint32) (uint, syscall.Errno) {
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

func sysMmap(addr, length uintptr, prot, flags, fd int, offset int64) (unsafe.Pointer, error) {
	ptr, err := mmap(addr, length, prot, flags, fd, offset)

	return unsafe.Pointer(ptr), err
}

func sysMunmap(addr, length uintptr) error {
	return munmap(addr, length)
}

//go:linkname mmap syscall.mmap
func mmap(addr uintptr, length uintptr, prot int, flags int, fd int, offset int64) (xaddr uintptr, err error)

//go:linkname munmap syscall.munmap
func munmap(addr uintptr, length uintptr) (err error)
