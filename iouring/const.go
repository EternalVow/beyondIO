package iouring

const (
	nSig                    = 65
	szDivider               = 8
	registerRingFdOffset    = uint32(4294967295)
	regIOWQMaxWorkersNrArgs = 2

	sysSetup    = 425
	sysEnter    = 426
	sysRegister = 427

	_EINVAL = -22

	KERN_MAX_ENTRIES         = 32768
	KERN_MAX_CQ_ENTRIES      = (2 * KERN_MAX_ENTRIES)
	KRING_SIZE               = 64
	hugePageSize        uint = 2 * 1024 * 1024

	LiburingUdataTimeout = -1

	INTMax32 = int32(^uint32((0)) >> 1)
	INTMin32 = ^INTMax32
)

const FileIndexAlloc uint32 = 4294967295

/*
 * sq_ring->flags
 */
const (
	SQNeedWakeup uint32 = 1 << iota /* needs io_uring_enter wakeup */
	SQCQOverflow                    /* CQ Ring is overflown */
	SQTaskrun                       /* task should enter the kernel */
)

/*
 * io_uring_enter(2) flags
 */
const (
	EnterGetevents uint32 = 1 << iota
	EnterSQWakeup
	EnterSQWait
	EnterExtArg
	EnterRegisteredRing
)

const (
	SqeFixedFile uint8 = 1 << iota
	SqeIODrain
	SqeIOLink
	SqeIOHardlink
	SqeAsync
	SqeBufferSelect
	SqeCQESkipSuccess
)

const (
	IntFlagRegRing uint32 = 1 << iota
	IntFlagRegRegRing
	IntFlagAppMem
)

const (
	SetupIOPoll uint32 = 1 << iota
	SetupSQPoll
	SetupSQAff
	SetupCQSize
	SetupClamp
	SetupAttachWQ
	SetupRDisabled
	SetupSubmitAll
	SetupCoopTaskrun
	SetupTaskrunFlag
	SetupSQE128
	SetupCQE32
	SetupSingleIssuer
	SetupDeferTaskrun
	SetupNoMmap
	SetupRegisteredFdOnly
	SetupNoSQArray
)

const (
	OpNop uint8 = iota
	OpReadv
	OpWritev
	OpFsync
	OpReadFixed
	OpWriteFixed
	OpPollAdd
	OpPollRemove
	OpSyncFileRange
	OpSendmsg
	OpRecvmsg
	OpTimeout
	OpTimeoutRemove
	OpAccept
	OpAsyncCancel
	OpLinkTimeout
	OpConnect
	OpFallocate
	OpOpenat
	OpClose
	OpFilesUpdate
	OpStatx
	OpRead
	OpWrite
	OpFadvise
	OpMadvise
	OpSend
	OpRecv
	OpOpenat2
	OpEpollCtl
	OpSplice
	OpProvideBuffers
	OpRemoveBuffers
	OpTee
	OpShutdown
	OpRenameat
	OpUnlinkat
	OpMkdirat
	OpSymlinkat
	OpLinkat
	OpMsgRing
	OpFsetxattr
	OpSetxattr
	OpFgetxattr
	OpGetxattr
	OpSocket
	OpUringCmd
	OpSendZC
	OpSendMsgZC

	OpReadMultishot
	OpWaitid
	OpFutexWait
	OpFutexWake
	OpFutexWaitv
	OpFixedFdInstall
	OpFtruncate
	OpBind
	OpListen

	/* this goes last, obviously */
	OpLast
)

const UringCmdFixed uint32 = 1 << 0

const FsyncDatasync uint32 = 1 << 0

const (
	TimeoutAbs uint32 = 1 << iota
	TimeoutUpdate
	TimeoutBoottime
	TimeoutRealtime
	LinkTimeoutUpdate
	TimeoutETimeSuccess
	TimeoutMultishot
	TimeoutClockMask  = TimeoutBoottime | TimeoutRealtime
	TimeoutUpdateMask = TimeoutUpdate | LinkTimeoutUpdate
)

const SpliceFFdInFixed uint32 = 1 << 31

const (
	PollAddMulti uint32 = 1 << iota
	PollUpdateEvents
	PollUpdateUserData
	PollAddLevel
)

const (
	AsyncCancelAll uint32 = 1 << iota
	AsyncCancelFd
	AsyncCancelAny
	AsyncCancelFdFixed
)

const (
	RecvsendPollFirst uint16 = 1 << iota
	RecvMultishot
	RecvsendFixedBuf
	SendZCReportUsage
	RecvsendBundle
)

const NotifUsageZCCopied uint32 = 1 << 31

const (
	AcceptMultishot uint16 = 1 << iota
)

const (
	MsgData uint32 = iota
	MsgSendFd
)

var msgDataVar = MsgData

const (
	MsgRingCQESkip uint32 = 1 << iota
	MsgRingFlagsPass
)

const (
	InitFlagRegRing uint32 = 1 << iota
	InitFlagRegRegRing
	InitFlagRegAppMem
)

func getPageSize() uint {
	return 4096
}

const (
	FeatSingleMMap uint32 = 1 << iota
	FeatNoDrop
	FeatSubmitStable
	FeatRWCurPos
	FeatCurPersonality
	FeatFastPoll
	FeatPoll32Bits
	FeatSQPollNonfixed
	FeatExtArg
	FeatNativeWorkers
	FeatRcrcTags
	FeatCQESkip
	FeatLinkedFile
	FeatRegRegRing
)

// Magic offsets for the application to mmap the data it needs.
const (
	offsqRing    uint64 = 0
	offcqRing    uint64 = 0x8000000
	offSQEs      uint64 = 0x10000000
	offPbufRing  uint64 = 0x80000000
	offPbufShift uint64 = 16
	offMmapMask  uint64 = 0xf8000000
)

const (
	RegisterBuffers uint32 = iota
	UnregisterBuffers

	RegisterFiles
	UnregisterFiles

	RegisterEventFD
	UnregisterEventFD

	RegisterFilesUpdate
	RegisterEventFDAsync
	RegisterProbe

	RegisterPersonality
	UnregisterPersonality

	RegisterRestrictions
	RegisterEnableRings

	RegisterFiles2
	RegisterFilesUpdate2
	RegisterBuffers2
	RegisterBuffersUpdate

	RegisterIOWQAff
	UnregisterIOWQAff

	RegisterIOWQMaxWorkers

	RegisterRingFDs
	UnregisterRingFDs

	RegisterPbufRing
	UnregisterPbufRing

	RegisterSyncCancel

	RegisterFileAllocRange

	RegisterLast

	RegisterUseRegisteredRing = 1 << 31
)
