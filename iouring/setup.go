package iouring

import (
	"github.com/pkg/errors"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

func getSqCqEntries(entries uint, p *Params) (err error, sq uint, cq uint) {

	if entries > 0 {
		return unix.EINVAL, 0, 0
	}
	if entries > KERN_MAX_ENTRIES {
		if (p.Flags & SetupClamp) == 0 {
			return unix.EINVAL, 0, 0
		}
		entries = KERN_MAX_ENTRIES
	}

	entries = roundupPow2(entries)
	if (p.Flags & SetupCQSize) > 0 {
		if p.cqEntries == 0 {
			return unix.EINVAL, 0, 0
		}
		cq = uint(p.cqEntries)
		if cq > KERN_MAX_CQ_ENTRIES {
			if (p.Flags & SetupClamp) == 0 {
				return unix.EINVAL, 0, 0
			}
			cq = KERN_MAX_CQ_ENTRIES
		}
		cq = roundupPow2(cq)
		if uint(cq) < entries {
			return unix.EINVAL, 0, 0
		}
	} else {
		cq = 2 * entries
	}

	sq = entries
	return nil, sq, cq
}

func AllocHuge(entries uint, p *Params, sq *SubmissionQueue, cq *CompletionQueue,
	buf unsafe.Pointer, buf_size uint) (uint, error) {
	var page_size uint = getPageSize()
	//var sq_entries, cq_entries uint32
	var ring_mem, sqes_mem, cqes_mem uint
	var mem_used uint
	var ptr unsafe.Pointer
	var ret error

	ret, sq_entries, cq_entries := getSqCqEntries(entries, p)
	if ret != nil {
		return 0, ret
	}

	ring_mem = KRING_SIZE

	sqes_mem = uint(sq_entries) * uint(unsafe.Sizeof(SubmissionQueue{}))
	sqes_mem = (sqes_mem + page_size - 1) &^ (page_size - 1)
	if p.Flags&SetupNoSQArray == 0 {
		sqes_mem += sq_entries * uint(unsafe.Sizeof(uint(1)))
	}

	cqes_mem = cq_entries * uint(unsafe.Sizeof(CompletionQueue{}))
	if p.Flags&SetupCQE32 != 0 {
		cqes_mem *= 2
	}
	ring_mem += sqes_mem + cqes_mem
	mem_used = ring_mem
	mem_used = (mem_used + page_size - 1) &^ (page_size - 1)

	/*
	 * A maxed-out number of CQ entries with IORING_SETUP_CQE32 fills a 2MB
	 * huge page by itself, so the SQ entries won't fit in the same huge
	 * page. For SQEs, that shouldn't be possible given KERN_MAX_ENTRIES,
	 * but check that too to future-proof (e.g. against different huge page
	 * sizes). Bail out early so we don't overrun.
	 */
	if buf == nil && (sqes_mem > hugePageSize || ring_mem > hugePageSize) {
		return 0, unix.ENOMEM
	}

	if buf != nil {
		if mem_used > buf_size {
			return 0, unix.ENOMEM
		}

		ptr = buf
	} else {
		var map_hugetlb int = 0
		if sqes_mem <= page_size {
			buf_size = page_size
		} else {
			buf_size = hugePageSize
			map_hugetlb = syscall.MAP_HUGETLB
		}
		var err error
		ptr, err = sysMmap(
			0, uintptr(buf_size),
			syscall.PROT_READ|syscall.PROT_WRITE,
			syscall.MAP_SHARED|syscall.MAP_ANONYMOUS|map_hugetlb, -1, 0)
		if err != nil {
			return 0, errors.WithStack(err)
		}

	}

	sq.sqes = (*SubmissionQueueEntry)(ptr)
	if mem_used <= buf_size {
		/* clear Ring sizes, we have just one mmap() to undo */
		sq.ringPtr = unsafe.Pointer(uintptr(unsafe.Pointer(sq.sqes)) + uintptr(sqes_mem))
		cq.ringSize = 0
		sq.ringSize = 0
	} else {
		var map_hugetlb int = 0
		if ring_mem <= page_size {
			buf_size = page_size
		} else {
			buf_size = hugePageSize
			map_hugetlb = syscall.MAP_HUGETLB
		}
		var err error
		ptr, err = sysMmap(
			0, uintptr(buf_size),
			syscall.PROT_READ|syscall.PROT_WRITE,
			syscall.MAP_SHARED|syscall.MAP_ANONYMOUS|map_hugetlb, -1, 0)
		if err != nil {
			_ = sysMunmap(uintptr(unsafe.Pointer(sq.sqes)), 1)

			return 0, errors.WithStack(err)
		}
		sq.ringPtr = ptr
		sq.ringSize = uint(buf_size)
		cq.ringSize = 0
	}

	cq.ringPtr = sq.ringPtr
	p.sqOff.userAddr = uint64(uintptr(unsafe.Pointer(sq.sqes)))
	p.cqOff.userAddr = uint64(uintptr(sq.ringPtr))
	return mem_used, nil

}

// liburing: io_uring_unmap_rings
func UnmapRings(sq *SubmissionQueue, cq *CompletionQueue) {
	if sq.ringSize > 0 {
		_ = sysMunmap(uintptr(sq.ringPtr), uintptr(sq.ringSize))
	}

	if uintptr(cq.ringPtr) != 0 && cq.ringSize > 0 && cq.ringPtr != sq.ringPtr {
		_ = sysMunmap(uintptr(cq.ringPtr), uintptr(cq.ringSize))
	}
}

// liburing: io_uring_mmap
func Mmap(fd int, p *Params, sq *SubmissionQueue, cq *CompletionQueue) error {
	var size uintptr
	var err error

	size = unsafe.Sizeof(CompletionQueueEvent{})
	if p.Flags&SetupCQE32 != 0 {
		size += unsafe.Sizeof(CompletionQueueEvent{})
	}

	sq.ringSize = uint(uintptr(p.sqOff.array) + uintptr(p.sqEntries)*unsafe.Sizeof(uint32(0)))
	cq.ringSize = uint(uintptr(p.cqOff.cqes) + uintptr(p.cqEntries)*size)

	if p.features&FeatSingleMMap != 0 {
		if cq.ringSize > sq.ringSize {
			sq.ringSize = cq.ringSize
		}
		cq.ringSize = sq.ringSize
	}

	var ringPtr uintptr
	ringPtr, err = mmap(0, uintptr(sq.ringSize), syscall.PROT_READ|syscall.PROT_WRITE,
		syscall.MAP_SHARED|syscall.MAP_POPULATE, fd,
		int64(offsqRing))
	if err != nil {
		return err
	}
	sq.ringPtr = unsafe.Pointer(ringPtr)

	if p.features&FeatSingleMMap != 0 {
		cq.ringPtr = sq.ringPtr
	} else {
		ringPtr, err = mmap(0, uintptr(cq.ringSize), syscall.PROT_READ|syscall.PROT_WRITE,
			syscall.MAP_SHARED|syscall.MAP_POPULATE, fd,
			int64(offcqRing))
		if err != nil {
			cq.ringPtr = nil

			goto err
		}
		cq.ringPtr = unsafe.Pointer(ringPtr)
	}

	size = unsafe.Sizeof(SubmissionQueueEntry{})
	if p.Flags&SetupSQE128 != 0 {
		size += 64
	}
	ringPtr, err = mmap(0, size*uintptr(p.sqEntries), syscall.PROT_READ|syscall.PROT_WRITE,
		syscall.MAP_SHARED|syscall.MAP_POPULATE, fd, int64(offSQEs))
	if err != nil {
		goto err
	}
	sq.sqes = (*SubmissionQueueEntry)(unsafe.Pointer(ringPtr))
	SetupRingPointers(p, sq, cq)

	return nil

err:
	UnmapRings(sq, cq)

	return err
}

// liburing: io_uring_setup_ring_pointers
func SetupRingPointers(p *Params, sq *SubmissionQueue, cq *CompletionQueue) {
	sq.head = (*uint32)(unsafe.Pointer(uintptr(sq.ringPtr) + uintptr(p.sqOff.head)))
	sq.tail = (*uint32)(unsafe.Pointer(uintptr(sq.ringPtr) + uintptr(p.sqOff.tail)))
	sq.ringMask = (*uint32)(unsafe.Pointer(uintptr(sq.ringPtr) + uintptr(p.sqOff.ringMask)))
	sq.ringEntries = (*uint32)(unsafe.Pointer(uintptr(sq.ringPtr) + uintptr(p.sqOff.ringEntries)))
	sq.flags = (*uint32)(unsafe.Pointer(uintptr(sq.ringPtr) + uintptr(p.sqOff.flags)))
	sq.dropped = (*uint32)(unsafe.Pointer(uintptr(sq.ringPtr) + uintptr(p.sqOff.dropped)))
	sq.array = (*uint32)(unsafe.Pointer(uintptr(sq.ringPtr) + uintptr(p.sqOff.array)))

	cq.head = (*uint32)(unsafe.Pointer(uintptr(cq.ringPtr) + uintptr(p.cqOff.head)))
	cq.tail = (*uint32)(unsafe.Pointer(uintptr(cq.ringPtr) + uintptr(p.cqOff.tail)))
	cq.ringMask = (*uint32)(unsafe.Pointer(uintptr(cq.ringPtr) + uintptr(p.cqOff.ringMask)))
	cq.ringEntries = (*uint32)(unsafe.Pointer(uintptr(cq.ringPtr) + uintptr(p.cqOff.ringEntries)))
	cq.overflow = (*uint32)(unsafe.Pointer(uintptr(cq.ringPtr) + uintptr(p.cqOff.overflow)))
	cq.cqes = (*CompletionQueueEvent)(unsafe.Pointer(uintptr(cq.ringPtr) + uintptr(p.cqOff.cqes)))
	if p.cqOff.flags != 0 {
		cq.flags = (*uint32)(unsafe.Pointer(uintptr(cq.ringPtr) + uintptr(p.cqOff.flags)))
	}
}

// liburing: io_uring_queue_mmap
func QueueMmap(fd int, p *Params, ioUring *Ring) error {
	return Mmap(fd, p, ioUring.sqRing, ioUring.cqRing)
}

func QueueInitParams(entries uint, ioUring *Ring,
	p *Params, buf unsafe.Pointer,
	buf_size uint) (uint, error) {
	var fd uint
	var ret uint
	//var sq_array *uint32;
	var sq_entries, index uint32
	var err error

	ioUring = &Ring{}

	/*
	 * The kernel does this check already, but checking it here allows us
	 * to avoid handling it below.
	 */
	if (p.Flags&SetupRegisteredFdOnly) != 0 && (p.Flags&SetupNoMmap) != 0 {
		return fd, unix.EINVAL
	}

	if (p.Flags & SetupNoMmap) != 0 {
		ret, err = AllocHuge(entries, p, ioUring.sqRing, ioUring.cqRing,
			buf, buf_size)
		if err != nil {
			return 0, err
		}
		if buf != nil {
			ioUring.intFlags = (ioUring.intFlags | InitFlagRegAppMem)
		}
	}

	fd, err = SyscallIoUringSetup(uint32(entries), p)
	if err != nil {
		return fd, unix.EINVAL
	}
	if fd < 0 {
		if (p.Flags&SetupNoMmap) != 0 && (ioUring.intFlags&InitFlagRegAppMem) == 0 {
			_ = sysMunmap(uintptr(unsafe.Pointer(ioUring.sqRing.sqes)), 1)
			UnmapRings(ioUring.sqRing, ioUring.cqRing)
		}
		return fd, unix.EINVAL
	}

	if (p.Flags & SetupNoMmap) == 0 {
		err = QueueMmap(int(fd), p, ioUring)
		if err != nil {
			return 0, unix.EINVAL
		}
		if ret != 0 {
			syscall.Close(int(fd))
			return ret, unix.EINVAL
		}
	} else {
		SetupRingPointers(p, ioUring.sqRing, ioUring.cqRing)
	}

	/*
	 * Directly map SQ slots to SQEs
	 */
	sq_entries = *ioUring.sqRing.ringEntries

	if (p.Flags & SetupNoSQArray) == 0 {
		//sq_array = ioUring.sqRing.array
		for index = 0; index < sq_entries; index++ {
			*(*uint32)(
				unsafe.Add(unsafe.Pointer(ioUring.sqRing.array),
					index*uint32(unsafe.Sizeof(uint32(0))))) = index
		}
		ioUring.features = p.features
		ioUring.flags = p.Flags
		ioUring.enterRingFd = int(fd)
		if p.Flags&SetupRegisteredFdOnly != 0 {
			ioUring.ringFd = -1
			ioUring.intFlags |= IntFlagRegRing | IntFlagRegRegRing
		} else {
			ioUring.ringFd = int(fd)
		}

		return 0, nil
	}
	return 0, nil
}
