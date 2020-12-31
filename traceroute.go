// Package traceroute provides functions for executing a tracroute to a remote
// host.
package traceroute

import (
	"errors"
	"fmt"
	"net"
	"time"

	"golang.org/x/sys/unix"
)

const (
	// DefaultPort is the default local src port (33434)
	DefaultPort = 33434
	// DefaultMaxHops is the default int of max hops (64)
	DefaultMaxHops = 64
	// DefaultFirstHop is the default first hop (1)
	DefaultFirstHop = 1
	// DefaultTimeoutMs is the default timeout in ms
	DefaultTimeoutMs = 500
	// DefaultRetries is the default number of times to retry
	DefaultRetries = 3
	// DefaultPacketSize is the default packet size
	DefaultPacketSize = 52
)

// Return the first non-loopback address as a 4 byte IP address. This address
// is used for sending packets out.
func socketAddr() (addr [4]byte, err error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return
	}

	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if len(ipnet.IP.To4()) == net.IPv4len {
				copy(addr[:], ipnet.IP.To4())
				return
			}
		}
	}
	err = errors.New("You do not appear to be connected to the Internet")
	return
}

// Given a host name convert it to a 4 byte IP address.
func destAddr(dest string) (destAddr [4]byte, err error) {
	addrs, err := net.LookupHost(dest)
	if err != nil {
		return
	}
	addr := addrs[0]

	ipAddr, err := net.ResolveIPAddr("ip", addr)
	if err != nil {
		return
	}
	copy(destAddr[:], ipAddr.IP.To4())
	return
}

// Options is the struct for options
type Options struct {
	port       int
	maxHops    int
	firstHop   int
	timeoutMs  int
	retries    int
	packetSize int
}

// Port sets a local port
func (options *Options) Port() int {
	if options.port == 0 {
		options.port = DefaultPort
	}
	return options.port
}

// SetPort also sets a port
func (options *Options) SetPort(port int) {
	options.port = port
}

// MaxHops sets the number of max hops
func (options *Options) MaxHops() int {
	if options.maxHops == 0 {
		options.maxHops = DefaultMaxHops
	}
	return options.maxHops
}

// SetMaxHops also sets the number of max hops
func (options *Options) SetMaxHops(maxHops int) {
	options.maxHops = maxHops
}

// FirstHop sets the first hop to track
func (options *Options) FirstHop() int {
	if options.firstHop == 0 {
		options.firstHop = DefaultFirstHop
	}
	return options.firstHop
}

// SetFirstHop also sets the first hop to track
func (options *Options) SetFirstHop(firstHop int) {
	options.firstHop = firstHop
}

// TimeoutMs sets the default timeout in ms
func (options *Options) TimeoutMs() int {
	if options.timeoutMs == 0 {
		options.timeoutMs = DefaultTimeoutMs
	}
	return options.timeoutMs
}

// SetTimeoutMs also sets the default timeout in ms
func (options *Options) SetTimeoutMs(timeoutMs int) {
	options.timeoutMs = timeoutMs
}

// Retries sets the number of retries
func (options *Options) Retries() int {
	if options.retries == 0 {
		options.retries = DefaultRetries
	}
	return options.retries
}

// SetRetries also sets the number of retries
func (options *Options) SetRetries(retries int) {
	options.retries = retries
}

// PacketSize sets the packet size
func (options *Options) PacketSize() int {
	if options.packetSize == 0 {
		options.packetSize = DefaultPacketSize
	}
	return options.packetSize
}

// SetPacketSize also sets the packet size
func (options *Options) SetPacketSize(packetSize int) {
	options.packetSize = packetSize
}

// Hop type
type Hop struct {
	Success     bool
	Address     [4]byte
	Host        string
	N           int
	ElapsedTime time.Duration
	TTL         int
}

// AddressString returns a hop address as a string
func (hop *Hop) AddressString() string {
	return fmt.Sprintf("%v.%v.%v.%v", hop.Address[0], hop.Address[1], hop.Address[2], hop.Address[3])
}

// HostOrAddressString returns a hostname or address string
func (hop *Hop) HostOrAddressString() string {
	hostOrAddr := hop.AddressString()
	if hop.Host != "" {
		hostOrAddr = hop.Host
	}
	return hostOrAddr
}

// Result is a traceroute result struct
type Result struct {
	DestinationAddress [4]byte
	Hops               []Hop
}

func notify(hop Hop, channels []chan Hop) {
	for _, c := range channels {
		c <- hop
	}
}

func closeNotify(channels []chan Hop) {
	for _, c := range channels {
		close(c)
	}
}

// Traceroute uses the given dest (hostname) and options to execute a traceroute
// from your machine to the remote host.
//
// Outbound packets are UDP packets and inbound packets are ICMP.
//
// Returns a Result which contains an array of hops. Each hop includes
// the elapsed time and its IP address.
func Traceroute(dest string, options *Options, c ...chan Hop) (result Result, err error) {
	result.Hops = []Hop{}
	destAddr, err := destAddr(dest)
	result.DestinationAddress = destAddr
	socketAddr, err := socketAddr()
	if err != nil {
		return
	}

	timeoutMs := (int64)(options.TimeoutMs())
	tv := unix.NsecToTimeval(1000 * 1000 * timeoutMs)

	ttl := options.FirstHop()
	retry := 0
	for {
		//log.Println("TTL: ", ttl)
		start := time.Now()

		// Set up the socket to receive inbound packets
		recvSocket, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_ICMP)
		if err != nil {
			return result, err
		}

		// Set up the socket to send packets out.
		sendSocket, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, unix.IPPROTO_UDP)
		if err != nil {
			return result, err
		}
		// This sets the current hop TTL
		unix.SetsockoptInt(sendSocket, 0x0, unix.IP_TTL, ttl)
		// This sets the timeout to wait for a response from the remote host
		unix.SetsockoptTimeval(recvSocket, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)

		defer unix.Close(recvSocket)
		defer unix.Close(sendSocket)

		// Bind to the local socket to listen for ICMP packets
		unix.Bind(recvSocket, &unix.SockaddrInet4{Port: options.Port(), Addr: socketAddr})

		// Send a single null byte UDP packet
		unix.Sendto(sendSocket, []byte{0x0}, 0, &unix.SockaddrInet4{Port: options.Port(), Addr: destAddr})

		var p = make([]byte, options.PacketSize())
		n, from, err := unix.Recvfrom(recvSocket, p, 0)
		elapsed := time.Since(start)
		if err == nil {
			currAddr := from.(*unix.SockaddrInet4).Addr

			hop := Hop{Success: true, Address: currAddr, N: n, ElapsedTime: elapsed, TTL: ttl}

			// TODO: this reverse lookup appears to have some standard timeout that is relatively
			// high. Consider switching to something where there is greater control.
			currHost, err := net.LookupAddr(hop.AddressString())
			if err == nil {
				hop.Host = currHost[0]
			}

			notify(hop, c)

			result.Hops = append(result.Hops, hop)

			ttl++
			retry = 0

			if ttl > options.MaxHops() || currAddr == destAddr {
				closeNotify(c)
				return result, nil
			}
		} else {
			retry++
			if retry > options.Retries() {
				notify(Hop{Success: false, TTL: ttl}, c)
				ttl++
				retry = 0
			}

			if ttl > options.MaxHops() {
				closeNotify(c)
				return result, nil
			}
		}

	}
}
