package beyondIO

import "runtime"

var (
	EventLoopIndexMax = 10000
	EventLoopForCpu   = runtime.NumCPU()

	MaxStreamBufferCap = 1024 * 1024 * 512 // 512 mb
	DefaultBufferSize  = 1024 * 10         // 10 kb

	MAX_EVENTS = 500
)
