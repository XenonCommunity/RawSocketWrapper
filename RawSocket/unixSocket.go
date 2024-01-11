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

func OpenRawSocket(protocol ProtocolType) (*RawSocket, error) {
	sock, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, int(protocol))

	if err != nil {
		return nil, err
	}

	if err := syscall.SetsockoptInt(sock, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1); err != nil {
		return nil, err
	}
	if err := syscall.SetsockoptInt(sock, syscall.IPPROTO_IP, syscall.SO_REUSEADDR, 1); err != nil {
		return nil, err
	}

	conn, err := net.FilePacketConn(os.NewFile(uintptr(sock), strconv.Itoa(sock)))
	if err != nil {
		return nil, err
	}

	return &RawSocket{
		Write: func(bytes []byte, addr net.Addr) (int, error) {
			return conn.WriteTo(bytes, addr)
		},
		Read: func(bytes []byte) (int, net.Addr, error) {
			return conn.ReadFrom(bytes)
		},
		Close: func() error {
			return conn.Close()
		},
	}, nil
}
