package iouring

import (
	"errors"
	"syscall"
	"unsafe"
)

func doRegister(ioUring *Ring, opcode uint, arg unsafe.Pointer, nr_args uint) (uint, error) {
	var fd int
	if ioUring.intFlags&IntFlagRegRegRing > 0 {
		opcode |= RegisterUseRegisteredRing
		fd = ioUring.enterRingFd
	} else {
		fd = ioUring.ringFd
	}

	return SyscallIoUringRegister(fd, uint32(opcode), arg, uint32(nr_args))

}

// io_uring_register_ring_fd
func DoRegisterRingFd(ioUring *Ring) (uint, error) {
	up := RsrcUpdate{
		data:   uint64(ioUring.ringFd),
		offset: uint32(INTMax32),
	}
	if ioUring.intFlags&IntFlagRegRing > 0 {
		return 0, errors.New("-EEXIST")
	}
	ret, err := doRegister(ioUring, uint(RegisterRingFDs), unsafe.Pointer(&up), 1)
	if err != nil {
		return 0, err
	}
	if ret == 1 {
		ioUring.enterRingFd = int(up.offset)
		ioUring.intFlags |= IntFlagRegRing
		if ioUring.features&FeatRegRegRing > 0 {
			ioUring.intFlags |= IntFlagRegRegRing
		}
	}
	return ret, nil
}

// io_uring_unregister_ring_fd
func DoUnregisterRingFd(ioUring *Ring) (uint, error) {
	up := RsrcUpdate{
		offset: uint32(ioUring.enterRingFd),
	}
	if ioUring.intFlags&IntFlagRegRing > 0 {
		return 0, errors.New("-EINVAL")
	}
	ret, err := doRegister(ioUring, uint(UnregisterRingFDs), unsafe.Pointer(&up), 1)
	if err != nil {
		return 0, err
	}
	if ret == 1 {
		ioUring.enterRingFd = int(ioUring.ringFd)
		ioUring.intFlags &= ^(IntFlagRegRing | IntFlagRegRegRing)
	}
	return ret, nil
}

// io_uring_register_buffers
func DoRegisterBuffers(ioUring *Ring, iovecs *syscall.Iovec, nr_iovecs uint) (uint, error) {
	return doRegister(ioUring, uint(RegisterBuffers), unsafe.Pointer(iovecs), nr_iovecs)
}

// io_uring_unregister_buffers
func DoUnRegisterBuffers(ioUring *Ring) (uint, error) {
	return doRegister(ioUring, uint(UnregisterBuffers), nil, 0)
}

func DoRegisterFiles(ioUring *Ring, files *int, nr_files uint) (uint, error) {
	var ret, did_increase uint
	var err error
	for {
		ret, err = doRegister(ioUring, uint(RegisterFiles), unsafe.Pointer(files), nr_files)
		if err != nil {
			return 0, err
		}
		if ret >= 0 {
			break
		}
		if did_increase == 0 {
			did_increase = 1
			increaseRlimitNofile(uint64(nr_files))
			continue
		}
		break
	}

	return ret, nil
}

// io_uring_unregister_files
func DoUnregisterFiles(ioUring *Ring) (uint, error) {
	return doRegister(ioUring, uint(UnregisterFiles), nil, 0)
}

// io_uring_register_eventfd
func DoRegisterEventfd(ioUring *Ring, event_fd int) (uint, error) {
	return doRegister(ioUring, uint(RegisterEventFD), unsafe.Pointer(&event_fd), 1)
}

// io_uring_unregister_eventfd
func DoUnregisterEventfd(ioUring *Ring, event_fd int) (uint, error) {
	return doRegister(ioUring, uint(UnregisterEventFD), nil, 0)
}

// io_uring_register_eventfd_async
func DoRegisterEventfdAsync(ioUring *Ring, event_fd int) (uint, error) {
	return doRegister(ioUring, uint(RegisterEventFDAsync), unsafe.Pointer(&event_fd), 1)
}
