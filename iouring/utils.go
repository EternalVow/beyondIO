package iouring

import "unsafe"

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
