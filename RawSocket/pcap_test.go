package RawSocket

import (
	"math"
	"net"
	"testing"
)

// TestPcapSocket_Write tests the Write function of PcapSocket.
func TestPcapSocket_Write(t *testing.T) {
	t.Log("TestPcapSocket_Write")

	pcapSocket, err := OpenRawSocket(IPPROTO_TCP)
	if err != nil {
		t.Error(err)
		return
	}

	// Create a TCP packet with SYN flag set and randomize flag enabled.
	tcp := TCP{SYN: true, Randomize: true}

	// Get the IP address of the current machine.
	src := net.TCPAddr{IP: GetSelfIP()}

	// Set the destination IP address and port.
	dest := net.TCPAddr{
		IP:   net.IPv4(8, 8, 8, 8),
		Port: 443,
	}

	// Build the TCP packet using the source and destination addresses.
	packet := tcp.Build(src, dest)

	// Write the packet to the pcap socket and get the number of bytes written.
	n, err := pcapSocket.Write(packet, &net.IPAddr{IP: dest.IP})
	if err != nil {
		t.Error(err)
		return
	}

	// Log the successful packet send with the length of the packet in bytes.
	t.Logf("Packet sent, Length: %d bytes", n)
}

// TestPcapSocket_Read tests the Read function of the PcapSocket type.
func TestPcapSocket_Read(t *testing.T) {
	t.Log("TestPcapSocket_Read")

	// Open a raw socket with TCP protocol
	pcapSocket, err := OpenRawSocket(IPPROTO_TCP)
	if err != nil {
		t.Error(err)
		return
	}

	// Create a buffer to hold the received data
	var buff = make([]byte, math.MaxUint16)

	// Read 5 packets from the pcap socket
	for i := 0; i < 5; i++ {
		// Read data from the pcap socket
		n, addr, err := pcapSocket.Read(buff)

		// If there is an error, fail the test and break out of the loop
		if err != nil {
			t.Error(err)
			break
		}

		// Log the received packet and its source address
		t.Logf("Packet %v received from %s", buff[:n], addr)
	}
}
