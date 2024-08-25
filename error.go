package beyondIO

import "errors"

var (
	// ErrEmptyEngine occurs when trying to do something with an empty engine.
	ErrEmptyEngine = errors.New(" the internal engine is empty")
	// ErrEngineShutdown occurs when server is closing.
	ErrEngineShutdown = errors.New(" server is going to be shutdown")
	// ErrEngineInShutdown occurs when attempting to shut the server down more than once.
	ErrEngineInShutdown = errors.New(" server is already in shutdown")
	// ErrAcceptSocket occurs when acceptor does not accept the new connection properly.
	ErrAcceptSocket = errors.New(" accept a new connection error")
	// ErrTooManyEventLoopThreads occurs when attempting to set up more than 10,000 event-loop goroutines under LockOSThread mode.
	ErrTooManyEventLoopThreads = errors.New(" too many event-loops under LockOSThread mode")
	// ErrUnsupportedProtocol occurs when trying to use protocol that is not supported.
	ErrUnsupportedProtocol = errors.New(" only unix, tcp/tcp4/tcp6, udp/udp4/udp6 are supported")
	// ErrUnsupportedTCPProtocol occurs when trying to use an unsupported TCP protocol.
	ErrUnsupportedTCPProtocol = errors.New(" only tcp/tcp4/tcp6 are supported")
	// ErrUnsupportedUDPProtocol occurs when trying to use an unsupported UDP protocol.
	ErrUnsupportedUDPProtocol = errors.New(" only udp/udp4/udp6 are supported")
	// ErrUnsupportedUDSProtocol occurs when trying to use an unsupported Unix protocol.
	ErrUnsupportedUDSProtocol = errors.New(" only unix is supported")
	// ErrUnsupportedPlatform occurs when running gnet on an unsupported platform.
	ErrUnsupportedPlatform = errors.New(" unsupported platform in gnet")
	// ErrUnsupportedOp occurs when calling some methods that has not been implemented yet.
	ErrUnsupportedOp = errors.New(" unsupported operation")
	// ErrNegativeSize occurs when trying to pass a negative size to a buffer.
	ErrNegativeSize = errors.New(" negative size is not allowed")
	// ErrNoIPv4AddressOnInterface occurs when an IPv4 multicast address is set on an interface but IPv4 is not configured.
	ErrNoIPv4AddressOnInterface = errors.New(" no IPv4 address on interface")
	// ErrInvalidNetworkAddress occurs when the network address is invalid.
	ErrInvalidNetworkAddress = errors.New(" invalid network address")
)
