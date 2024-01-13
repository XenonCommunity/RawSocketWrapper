package RawSocket

import (
	"net"
	"strings"
	"time"
)

// getIfaceIP returns the IP address of the first available network interface that is not loopback.
func getIfaceIP() net.IP {
	// Get all network interfaces
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}

	// Iterate through each network interface
	for _, i := range ifaces {
		// Skip interfaces that are up or loopback
		if i.Flags&net.FlagUp != 0 || i.Flags&net.FlagLoopback != 0 {
			continue
		}

		// Get the addresses of the current interface
		addrs, err := i.Addrs()
		if err != nil {
			continue
		}

		// Iterate through each address
		for _, a := range addrs {
			switch v := a.(type) {
			// If the address is of type *net.IPAddr
			case *net.IPAddr:
				// Skip loopback addresses and addresses that are not IPv4
				if v.IP.IsLoopback() || v.IP.To4() == nil {
					continue
				}
				return v.IP

			// If the address is of type *net.IPNet
			case *net.IPNet:
				// Skip loopback addresses and addresses that are not IPv4
				if v.IP.IsLoopback() || v.IP.To4() == nil {
					continue
				}
				return v.IP
			}
		}
	}

	return nil
}

// requestIP requests the IP address by making a TCP connection to a specified server.
// It sends a HEAD request to the server and returns the local IP address if successful.
// Otherwise, it returns nil.
func requestIP() net.IP {
	// Make a TCP connection to the server
	conn, err := net.DialTimeout("tcp", "1.1.1.1:80", time.Second)
	if err != nil {
		// Return nil if connection fails
		return nil
	}
	defer conn.Close()

	// Send a HEAD request to the server
	_, err = conn.Write([]byte(
		"HEAD /?amongus HTTP/1.1\r\n" +
			"Host: one.one.one.one\r\n" +
			"Connection: Close\r\n\r\n"))
	if err != nil {
		// Return nil if request fails
		return nil
	}

	// Get the local IP address from the connection
	localAddr := conn.LocalAddr().String()
	ip := strings.Split(localAddr, ":")[0]
	return net.ParseIP(ip)
}

var selfIP net.IP

// GetSelfIP returns the IP address of the current machine.
func GetSelfIP() net.IP {
	// Check if selfIP has already been set
	if selfIP != nil {
		// Return the previously set selfIP
		return selfIP
	}

	// Get the IP address using the requestIP function
	selfIP = requestIP()

	// If the IP address is not available, get it using the getIfaceIP function
	if selfIP == nil {
		selfIP = getIfaceIP()
	}

	// Return the final selfIP
	return selfIP
}
