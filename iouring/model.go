package iouring

import "unsafe"

// liburing: io_sqring_offsets
type SQRingOffsets struct {
	head        uint32
	tail        uint32
	ringMask    uint32
	ringEntries uint32
	flags       uint32
	dropped     uint32
	array       uint32
	resv1       uint32
	userAddr    uint64
}

// liburing: io_cqring_offsets
type CQRingOffsets struct {
	head        uint32
	tail        uint32
	ringMask    uint32
	ringEntries uint32
	overflow    uint32
	cqes        uint32
	flags       uint32
	resv1       uint32
	userAddr    uint64
}

// liburing: io_uring_params
type Params struct {
	sqEntries    uint32
	cqEntries    uint32
	flags        uint32
	sqThreadCPU  uint32
	sqThreadIdle uint32
	features     uint32
	wqFd         uint32
	resv         [3]uint32

	sqOff SQRingOffsets
	cqOff CQRingOffsets
}

type SubmissionQueueEntry struct {
	OpCode      uint8
	Flags       uint8
	IoPrio      uint16
	Fd          int32
	Off         uint64
	Addr        uint64
	Len         uint32
	OpcodeFlags uint32
	UserData    uint64
	BufIG       uint16
	Personality uint16
	SpliceFdIn  int32
	Addr3       uint64
	_pad2       [1]uint64
}

type CompletionQueueEvent struct {
	UserData uint64
	Res      int32
	Flags    uint32
}

// liburing: io_uring_sq
type SubmissionQueue struct {
	head        *uint32
	tail        *uint32
	ringMask    *uint32
	ringEntries *uint32
	flags       *uint32
	dropped     *uint32
	array       *uint32
	sqes        *SubmissionQueueEntry

	ringSize uint
	ringPtr  unsafe.Pointer

	sqeHead uint32
	sqeTail uint32

	// nolint: unused
	pad [2]uint32
}

// liburing: io_uring_cq
type CompletionQueue struct {
	head        *uint32
	tail        *uint32
	ringMask    *uint32
	ringEntries *uint32
	flags       *uint32
	overflow    *uint32
	cqes        *CompletionQueueEvent

	ringSize uint
	ringPtr  unsafe.Pointer

	pad [2]uint32
}

// liburing: io_uring
type Ring struct {
	sqRing      *SubmissionQueue
	cqRing      *CompletionQueue
	flags       uint32
	ringFd      int
	features    uint32
	enterRingFd int
	intFlags    uint8
	pad         [3]uint8
	pad2        uint32
}
