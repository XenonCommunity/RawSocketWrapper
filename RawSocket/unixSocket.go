//go:build !windows

package RawSocket

import (
	"net"
	"os"
	"strconv"
	"syscall"
)

type ProtocolType int

//goland:noinspection GoUnusedGlobalVariable,GoSnakeCaseUsage
var (
	IPPROTO_TCP  = ProtocolType(syscall.IPPROTO_TCP)
	IPPROTO_UDP  = ProtocolType(syscall.IPPROTO_UDP)
	IPPROTO_ICMP = ProtocolType(syscall.IPPROTO_ICMP)
	IPPROTO_RAW  = ProtocolType(syscall.IPPROTO_RAW)
	IPPROTO_IP   = ProtocolType(syscall.IPPROTO_IP)
)

type UnixSocket struct {
	conn net.PacketConn
}

// newUnixSocket creates a new UnixSocket instance with the given PacketConn.
func newUnixSocket(conn net.PacketConn) *UnixSocket {
	return &UnixSocket{conn: conn}
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
	return newUnixSocket(conn), nil
}
