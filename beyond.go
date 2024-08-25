package beyondIO

import (
	"runtime"
	"strings"
)

// Run starts handling events on the specified address.
//
// Address should use a scheme prefix and be formatted
// like `tcp://192.168.0.10:9851` or `unix://socket`.
// Valid network schemes:
//
//	tcp   - bind to both IPv4 and IPv6
//	tcp4  - IPv4
//	tcp6  - IPv6
//	udp   - bind to both IPv4 and IPv6
//	udp4  - IPv4
//	udp6  - IPv6
//	unix  - Unix Domain Socket
//
// The "tcp" network scheme is assumed when one is not specified.
func Run(eventHandler EventHandler, protoAddr string, opts ...Option) error {
	listeners, options, err := createListeners([]string{protoAddr}, opts...)
	if err != nil {
		return err
	}
	defer func() {
		for _, ln := range listeners {
			ln.close()
		}
	}()
	return run(eventHandler, listeners, options, []string{protoAddr})
}

func createListeners(addrs []string, opts ...Option) ([]*listener, *Options, error) {
	options := loadOptions(opts...)

	// The maximum number of operating system threads that the Go program can use is initially set to 10000,
	// which should also be the maximum amount of I/O event-loops locked to OS threads that users can start up.
	if options.LockOSThread && options.NumEventLoop > 10000 {
		return nil, nil, ErrTooManyEventLoopThreads
	}

	rbc := options.ReadBufferCap
	switch {
	case rbc <= 0:
		options.ReadBufferCap = MaxStreamBufferCap

	default:
		options.ReadBufferCap = DefaultBufferSize
	}
	wbc := options.WriteBufferCap
	switch {
	case wbc <= 0:
		options.WriteBufferCap = MaxStreamBufferCap
	default:
		options.WriteBufferCap = DefaultBufferSize
	}

	var hasUDP, hasUnix bool
	for _, addr := range addrs {
		proto, _, err := parseProtoAddr(addr)
		if err != nil {
			return nil, nil, err
		}
		hasUDP = hasUDP || strings.HasPrefix(proto, "udp")
		hasUnix = hasUnix || proto == "unix"
	}

	// SO_REUSEPORT enables duplicate address and port bindings across various
	// Unix-like OSs, whereas there is platform-specific inconsistency:
	// Linux implemented SO_REUSEPORT with load balancing for incoming connections
	// while *BSD implemented it for only binding to the same address and port, which
	// makes it pointless to enable SO_REUSEPORT on *BSD and Darwin for gnet with
	// multiple event-loops because only the first or last event-loop will be constantly
	// woken up to accept incoming connections and handle I/O events while the rest of
	// event-loops remain idle.
	// Thus, we disable SO_REUSEPORT on *BSD and Darwin by default.
	//
	// Note that FreeBSD 12 introduced a new socket option named SO_REUSEPORT_LB
	// with the capability of load balancing, it's the equivalent of Linux's SO_REUSEPORT.
	// Also note that DragonFlyBSD 3.6.0 extended SO_REUSEPORT to distribute workload to
	// available sockets, which make it the same as Linux's SO_REUSEPORT.
	//
	// Despite the fact that SO_REUSEPORT can be set on a Unix domain socket
	// via setsockopt() without reporting an error, SO_REUSEPORT is actually
	// not supported for sockets of AF_UNIX. Thus, we avoid setting it on the
	// Unix domain sockets.
	goos := runtime.GOOS
	if (options.Multicore || options.NumEventLoop > 1) && options.ReusePort &&
		((goos != "linux" && goos != "dragonfly" && goos != "freebsd") || hasUnix) {
		options.ReusePort = false
	}

	// If there is UDP address in the list, we have no choice but to enable SO_REUSEPORT anyway,
	// also disable edge-triggered I/O for UDP by default.
	if hasUDP {
		options.ReusePort = true
		options.EdgeTriggeredIO = false
	}

	listeners := make([]*listener, len(addrs))
	for i, a := range addrs {
		proto, addr, err := parseProtoAddr(a)
		if err != nil {
			return nil, nil, err
		}
		ln, err := initListener(proto, addr, options)
		if err != nil {
			return nil, nil, err
		}
		listeners[i] = ln
	}

	return listeners, options, nil
}

func parseProtoAddr(protoAddr string) (string, string, error) {
	protoAddr = strings.ToLower(protoAddr)
	if strings.Count(protoAddr, "://") != 1 {
		return "", "", ErrInvalidNetworkAddress
	}
	pair := strings.SplitN(protoAddr, "://", 2)
	proto, addr := pair[0], pair[1]
	switch proto {
	case "tcp", "tcp4", "tcp6", "udp", "udp4", "udp6", "unix":
	default:
		return "", "", ErrUnsupportedProtocol
	}
	if addr == "" {
		return "", "", ErrInvalidNetworkAddress
	}
	return proto, addr, nil
}
