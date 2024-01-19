//go:build !windows

package RawSocket

import (
	"github.com/google/gopacket"
	"math"

	"net"
	"os"
	"strconv"
	"syscall"
)

//goland:noinspection GoUnusedGlobalVariable,GoSnakeCaseUsage
var (
	IPPROTO_TCP  = ProtocolType(syscall.IPPROTO_TCP)
	IPPROTO_UDP  = ProtocolType(syscall.IPPROTO_UDP)
	IPPROTO_ICMP = ProtocolType(syscall.IPPROTO_ICMP)
	IPPROTO_RAW  = ProtocolType(syscall.IPPROTO_RAW)
	IPPROTO_IP   = ProtocolType(syscall.IPPROTO_IP)
)

type UnixSocket struct {
	conn     net.PacketConn
	protocol ProtocolType
}

var mtu = math.MaxInt16

func init() {
	iface, err := getInterfaceByIP(GetSelfIP())
	if err != nil {
		panic(err)
	}

	mtu = iface.MTU + 1
}

// newUnixSocket creates a new UnixSocket instance with the given PacketConn.
func newUnixSocket(conn net.PacketConn, protocol ProtocolType) *UnixSocket {
	return &UnixSocket{conn: conn, protocol: protocol}
}

// Write writes the given bytes to the specified address using the UnixSocket connection.
// It returns the number of bytes written and any error that occurred.
func (u *UnixSocket) Write(bytes []byte, addr net.Addr) (int, error) {
	return u.conn.WriteTo(bytes, addr)
}

// Read reads data from the Unix socket connection.
// It reads up to len(bytes) bytes into the provided byte slice.
// It returns the number of bytes read, the network address of the remote socket,
// and any error encountered.
func (u *UnixSocket) Read(bytes []byte) (int, net.Addr, error) {
	return u.conn.ReadFrom(bytes)
}

// Close closes the UnixSocket connection.
// It returns an error if there was an issue closing the connection.
func (u *UnixSocket) Close() error {
	return u.conn.Close()
}

// NextPacket reads the next packet from the UnixSocket.
// It returns the packet as a gopacket.Packet and any error encountered.
func (u *UnixSocket) NextPacket() (gopacket.Packet, *net.IPAddr, error) {
	// Create a byte slice with the maximum possible length of a packet.
	packetData := make([]byte, mtu)

	// Read the packet data into the byte slice.
	n, addr, err := u.Read(packetData)
	if err != nil {
		return nil, nil, err
	}

	// Create a new packet using the packet data and the LinkType of the UnixSocket.
	// Set the NoCopy option to indicate that the packet should not be copied.
	packet := gopacket.NewPacket(packetData[:n], u.protocol.LinkType(), gopacket.NoCopy)
	return packet, addr.(*net.IPAddr), nil
}

// Iter returns a channel that will receive gopacket.Packet objects.
func (u *UnixSocket) Iter() chan WrappedPacket {
	// Create a buffered channel with a capacity of 1024.
	packets := make(chan WrappedPacket, 1024)
	// Start a goroutine that will call the startIter method and pass the packets channel.
	go u.startIter(packets)
	// Return the packets channel.
	return packets
}

// startIter starts iterating over packets from the PcapSocket and sends them to the provided channel.
func (u *UnixSocket) startIter(packets chan WrappedPacket) {
	defer func() {
		_ = recover()
	}()

	// Continuously read packets from the PcapSocket until the channel is closed.
	for packets != nil {
		// Get the next packet from the PcapSocket.
		packet, addr, err := u.NextPacket()
		if err != nil {
			continue
		}

		// Send the packet to the packets channel.
		packets <- WrappedPacket{
			IPAddr: addr,
			Packet: packet,
		}
	}
}

// OpenRawSocket opens a raw socket for the specified protocol.
// It returns a pointer to RawSocket and an error, if any.
func OpenRawSocket(protocol ProtocolType) (RawSocket, error) {
	// Create a new raw socket
	sock, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, int(protocol))
	if err != nil {
		return nil, err
	}

	// Set socket options
	if err := syscall.SetsockoptInt(sock, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1); err != nil {
		return nil, err
	}

	if err := syscall.SetsockoptInt(sock, syscall.IPPROTO_IP, syscall.SO_REUSEADDR, 1); err != nil {
		return nil, err
	}

	// Convert the socket to a packet connection
	conn, err := net.FilePacketConn(os.NewFile(uintptr(sock), strconv.Itoa(sock)))
	if err != nil {
		return nil, err
	}

	// Create a RawSocket instance and return it
	return newUnixSocket(conn, protocol), nil
}
