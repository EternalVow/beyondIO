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
	Flags        uint32
	sqThreadCPU  uint32
	sqThreadIdle uint32
	features     uint32
	wqFd         uint32
	resv         [3]uint32

	sqOff SQRingOffsets
	cqOff CQRingOffsets
}

// liburing: io_uring_sqe
type SubmissionQueueEntry struct {
	OpCode uint8
	Flags  uint8
	IoPrio uint16
	Fd     int32
	// union {
	// 	__u64	off;	/* offset into file */
	// 	__u64	addr2;
	// 	struct {
	// 		__u32	cmd_op;
	// 		__u32	__pad1;
	// 	};
	// };
	Off uint64
	// union {
	// 	__u64	addr;	/* pointer to buffer or iovecs */
	// 	__u64	splice_off_in;
	// };
	Addr uint64
	Len  uint32
	// union {
	// 	__kernel_rwf_t	rw_flags;
	// 	__u32		fsync_flags;
	// 	__u16		poll_events;	/* compatibility */
	// 	__u32		poll32_events;	/* word-reversed for BE */
	// 	__u32		sync_range_flags;
	// 	__u32		msg_flags;
	// 	__u32		timeout_flags;
	// 	__u32		accept_flags;
	// 	__u32		cancel_flags;
	// 	__u32		open_flags;
	// 	__u32		statx_flags;
	// 	__u32		fadvise_advice;
	// 	__u32		splice_flags;
	// 	__u32		rename_flags;
	// 	__u32		unlink_flags;
	// 	__u32		hardlink_flags;
	// 	__u32		xattr_flags;
	// 	__u32		msg_ring_flags;
	// 	__u32		uring_cmd_flags;
	// };
	OpcodeFlags uint32
	UserData    uint64
	// union {
	// 	/* index into fixed buffers, if used */
	// 	__u16	buf_index;
	// 	/* for grouped buffer selection */
	// 	__u16	buf_group;
	// } __attribute__((packed));
	BufIG       uint16
	Personality uint16
	// union {
	// 	__s32	splice_fd_in;
	// 	__u32	file_index;
	// 	struct {
	// 		__u16	addr_len;
	// 		__u16	__pad3[1];
	// 	};
	// };
	SpliceFdIn int32
	Addr3      uint64
	_pad2      [1]uint64
	// TODO: add __u8	cmd[0];

	SpliceOffIn int32
	SpliceFlags int32
	RwFlags     uint8
}

// liburing: io_uring_cqe
type CompletionQueueEvent struct {
	UserData uint64
	Res      int32
	Flags    uint32

	// FIXME
	// 	__u64 big_cqe[];
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
	intFlags    uint32
	pad         [3]uint8
	pad2        uint32
}
