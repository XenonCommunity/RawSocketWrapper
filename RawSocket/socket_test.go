package RawSocket

import (
	"math"
	"net"
	"testing"
)

// TestUnixSocket_Write is a test function that tests the Write method of the UnixSocket type.
func TestUnixSocket_Write(t *testing.T) {
	t.Log("TestUnixSocket_Write")

	// Open a raw socket with TCP protocol
	unixSocket, err := OpenRawSocket(IPPROTO_TCP)
	if err != nil {
		t.Error(err)
		return
	}

	// Create a TCP object with SYN and Randomize set to true.
	tcp := TCP{SYN: true, Randomize: true}

	// Create the source TCP address using the GetSelfIP function.
	src := net.TCPAddr{IP: GetSelfIP()}

	// Create the destination TCP address with IP 8.8.8.8 and port 443.
	dest := net.TCPAddr{
		IP:   net.IPv4(8, 8, 8, 8),
		Port: 443,
	}

	// Build the TCP packet using the Build method of the TCP object.
	packet := tcp.Build(src, dest)

	// Create the IP address object for the destination IP.
	ipAddr := &net.IPAddr{IP: dest.IP}

	// Write the packet to the Unix socket using the Write method.
	n, err := unixSocket.Write(packet, ipAddr)
	if err != nil {
		t.Error(err)
		return
	}

	// Log the number of bytes sent in the packet.
	t.Logf("Packet sent, Length: %d bytes", n)
}

// TestUnixSocket_Read tests the Read function of the UnixSocket.
func TestUnixSocket_Read(t *testing.T) {
	// Log test name
	t.Log("TestUnixSocket_Read")

	// Open a raw socket with TCP protocol
	unixSocket, err := OpenRawSocket(IPPROTO_TCP)
	if err != nil {
		t.Error(err)
		return
	}

	// Create a buffer with maximum size
	var buff = make([]byte, math.MaxUint16)

	// Iterate 5 times
	for i := 0; i < 5; i++ {
		// Read from the UnixSocket
		n, addr, err := unixSocket.Read(buff)

		// Check for error
		if err != nil {
			t.Error(err)
			break
		}

		// Log received packet and its address
		t.Logf("Packet %v received from %s", buff[:n], addr)
	}
}
