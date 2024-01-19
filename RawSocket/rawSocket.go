package RawSocket

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"math"
	"math/rand"
	"net"
)

type ProtocolType int

// LinkType returns the corresponding gopacket.Decoder for the given ProtocolType.
func (t ProtocolType) LinkType() gopacket.Decoder {
	switch t {
	case IPPROTO_UDP:
		return layers.LayerTypeUDP
	case IPPROTO_ICMP:
		// Check if the IP address is IPv4 or IPv6
		ip := GetSelfIP()
		if ip.To4() != nil {
			return layers.LayerTypeICMPv4
		}
		return layers.LayerTypeICMPv6
	case IPPROTO_TCP:
		return layers.LayerTypeTCP
	case IPPROTO_IP:
		// Check if the IP address is IPv4 or IPv6
		ip := GetSelfIP()
		if ip.To4() != nil {
			return layers.LayerTypeIPv4
		}
		return layers.LayerTypeIPv6
	default:
		return layers.LayerTypeEthernet
	}
}

type TCP struct {
	SYN, ACK, RST, PSH, FIN, URG, ECE, CWR, NS bool
	Payload                                    []byte
	RandomizedPayloadLength                    int
	Options                                    []layers.TCPOption
	Sequence                                   uint32
	Randomize                                  bool
	Window                                     uint16
	AckNum                                     uint32
}

type UDP struct {
	Payload                 []byte
	RandomizedPayloadLength int
}

type ICMP struct {
	Type                    layers.ICMPv4TypeCode
	Payload                 []byte
	RandomizedPayloadLength int
}

type RawSocket interface {
	Write([]byte, net.Addr) (int, error)
	Read([]byte) (int, net.Addr, error)
	NextPacket() (gopacket.Packet, error)
	Iter() chan gopacket.Packet
	Close() error
}

var serializeOptions = gopacket.SerializeOptions{
	FixLengths:       true,
	ComputeChecksums: true,
}
var decodeOptions = gopacket.DecodeOptions{
	NoCopy: true,
}

func newSerializeBuffer() gopacket.SerializeBuffer {
	return gopacket.NewSerializeBuffer()
}

// newIPPacket returns a new network layer packet based on the source IP, destination IP, and protocol.
func newIPPacket(src, dest net.IP, protocol layers.IPProtocol) gopacket.NetworkLayer {
	// Check if the source IP is an IPv4 address
	if len(src) == net.IPv4len {
		// Create a new IPv4 packet
		return &layers.IPv4{
			Version:  4,                                // Set the IP version to 4
			Id:       uint16(rand.Intn(math.MaxInt16)), // Generate a random packet ID
			Flags:    layers.IPv4DontFragment,          // Set the Don't Fragment flag
			TTL:      uint8(rand.Intn(255) + 4),        // Set the Time-to-Live value
			Protocol: protocol,                         // Set the IP protocol
			SrcIP:    src,                              // Set the source IP address
			DstIP:    dest,                             // Set the destination IP address
		}
	} else {
		// Create a new IPv6 packet
		return &layers.IPv6{
			Version:    4,        // Set the IP version to 4
			NextHeader: protocol, // Set the next header protocol
			SrcIP:      src,      // Set the source IP address
			DstIP:      dest,     // Set the destination IP address
			HopByHop:   nil,      // Set the Hop-by-Hop extension header to nil
		}
	}
}

// Build generates a UDP packet with the provided source and destination addresses.
// It returns the serialized packet as a byte slice.
func (udp *UDP) Build(src, dest net.UDPAddr) []byte {
	// Create a buffer to store the serialized packet
	buffer := newSerializeBuffer()

	// Create an IP packet with the source and destination addresses
	ipPacket := newIPPacket(src.IP.To4(), dest.IP.To4(), layers.IPProtocolUDP)

	// Get valid source and destination ports
	dport := layers.UDPPort(validPort(dest.Port))
	sport := layers.UDPPort(validPort(src.Port))

	// Create a UDP layer with the source and destination ports
	udpLayer := &layers.UDP{
		SrcPort: sport,
		DstPort: dport,
	}

	// Set the UDP layer as the network layer for checksum calculation
	if err := udpLayer.SetNetworkLayerForChecksum(ipPacket); err != nil {
		return nil
	}

	// Generate random payload if specified
	if udp.RandomizedPayloadLength > 0 {
		udp.Payload = randomBytes(udp.RandomizedPayloadLength)
	}

	// Serialize the layers into the buffer
	if err := gopacket.SerializeLayers(buffer, serializeOptions, ipPacket.(gopacket.SerializableLayer), udpLayer, gopacket.Payload(udp.Payload)); err != nil {
		return nil
	}

	// Return the serialized packet as a byte slice
	return buffer.Bytes()
}

// Build constructs an ICMP packet with the given source and destination IP addresses.
// The function returns the byte representation of the constructed packet.
func (icmp *ICMP) Build(src, dest net.IPAddr) []byte {
	// Create a new serialize buffer to store the packet data
	buffer := newSerializeBuffer()

	// Create an IP packet with the source and destination IP addresses
	ipPacket := newIPPacket(src.IP.To4(), dest.IP.To4(), layers.IPProtocolICMPv4)

	// Create an ICMP layer with the specified type, random ID, and random sequence number
	icmpLayer := &layers.ICMPv4{
		TypeCode: icmp.Type,
		Id:       uint16(rand.Intn(math.MaxInt16)),
		Seq:      uint16(rand.Intn(math.MaxInt16)),
	}

	// If a randomized payload length is specified, generate a random payload
	if icmp.RandomizedPayloadLength > 0 {
		icmp.Payload = randomBytes(icmp.RandomizedPayloadLength)
	}

	// Convert the IP packet to a serializable layer
	layer := ipPacket.(gopacket.SerializableLayer)

	// Serialize the layers into the buffer, including the ICMP layer and payload if available
	if icmp.Payload != nil {
		if err := gopacket.SerializeLayers(buffer, serializeOptions, layer, icmpLayer, gopacket.Payload(icmp.Payload)); err != nil {
			return nil
		}
	} else {
		if err := gopacket.SerializeLayers(buffer, serializeOptions, layer, icmpLayer); err != nil {
			return nil
		}
	}

	// Return the byte representation of the constructed packet
	return buffer.Bytes()
}

// Build creates a TCP packet with the given source and destination addresses.
// It returns the serialized packet as a byte slice.
func (tcp *TCP) Build(src, dest net.TCPAddr) []byte {
	// Create a new serialize buffer
	buffer := newSerializeBuffer()

	// Create a new IP packet
	ipPacket := newIPPacket(src.IP.To4(), dest.IP.To4(), layers.IPProtocolTCP)

	// Get valid TCP ports
	dport := layers.TCPPort(validPort(dest.Port))
	sport := layers.TCPPort(validPort(src.Port))

	// Create a new TCP layer
	tcpLayer := &layers.TCP{
		SrcPort: sport,
		DstPort: dport,
		Seq:     tcp.Sequence,
		Window:  tcp.Window,
		Ack:     tcp.AckNum,
		FIN:     tcp.FIN,
		SYN:     tcp.SYN,
		RST:     tcp.RST,
		PSH:     tcp.PSH,
		ACK:     tcp.ACK,
		URG:     tcp.URG,
		ECE:     tcp.ECE,
		CWR:     tcp.CWR,
		NS:      tcp.NS,
	}

	// Add TCP options based on flags
	if tcp.ACK && tcp.SYN {
		// For SYN-ACK flag
		tcpLayer.Options = append(tcpLayer.Options,
			layers.TCPOption{
				OptionType: layers.TCPOptionKindSACK,
			},
		)
	} else if tcp.SYN {
		// For SYN flag
		tcpLayer.Options = append(tcpLayer.Options, layers.TCPOption{
			OptionType:   layers.TCPOptionKindMSS,
			OptionLength: 4,
			OptionData:   []byte{0x05, 0xb4}, // MSS value 1460 (0x05b4 in hexadecimal)
		}, layers.TCPOption{
			OptionType:   layers.TCPOptionKindWindowScale,
			OptionLength: 3,
			OptionData:   []byte{byte(rand.Intn(14))}, // random window scale
		}, layers.TCPOption{
			OptionType:   layers.TCPOptionKindTimestamps,
			OptionLength: 10,
			OptionData:   randomTimestamp(), // Fill with generated timestamp data
		}, layers.TCPOption{
			OptionType: layers.TCPOptionKindNop,
		}, layers.TCPOption{
			OptionType: layers.TCPOptionKindCCEcho,
		})
	} else if tcp.ACK {
		// For ACK flag
		if tcp.Randomize {
			tcpLayer.Ack = uint32(rand.Intn(math.MaxInt32) + 1)
		}

		tcpLayer.Options = append(tcpLayer.Options,
			layers.TCPOption{
				OptionType:   layers.TCPOptionKindWindowScale,
				OptionLength: 3,
				OptionData:   []byte{byte(rand.Intn(math.MaxInt8))}, // random window scale
			},
		)
	} else if tcp.FIN {
		// For FIN flag
		timestamp := randomTimestamp()
		tcpLayer.Options = append(tcpLayer.Options,
			layers.TCPOption{
				OptionType:   layers.TCPOptionKindTimestamps,
				OptionLength: uint8(len(timestamp)),
				OptionData:   timestamp, // Placeholder for timestamps
			},
		)
	}

	// Add additional TCP options
	if tcp.Options != nil && len(tcp.Options) > 0 {
		tcpLayer.Options = append(tcpLayer.Options, tcp.Options...)
	}

	// Randomize TCP sequence number and window size if specified
	if tcp.Randomize {
		tcpLayer.Seq = uint32(rand.Intn(math.MaxInt16) + 1)
		tcpLayer.Window = uint16(rand.Intn(math.MaxInt16) + 1)
	}

	// Set the network layer for checksum calculation
	if err := tcpLayer.SetNetworkLayerForChecksum(ipPacket); err != nil {
		return nil
	}

	// Randomize TCP payload length and content if specified
	if tcp.Randomize {
		if tcp.RandomizedPayloadLength > 0 {
			tcp.Payload = randomBytes(tcp.RandomizedPayloadLength)
		}
	}

	layer := ipPacket.(gopacket.SerializableLayer)

	// Serialize the packet with or without payload
	if tcp.Payload != nil {
		if err := gopacket.SerializeLayers(buffer, serializeOptions, layer, tcpLayer, gopacket.Payload(tcp.Payload)); err != nil {
			return nil
		}
	} else {
		if err := gopacket.SerializeLayers(buffer, serializeOptions, layer, tcpLayer); err != nil {
			return nil
		}
	}

	return buffer.Bytes()
}
