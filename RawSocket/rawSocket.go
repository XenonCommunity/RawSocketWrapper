package RawSocket

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"math"
	"math/rand"
	"net"
)

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

type RawSocket struct {
	Write func([]byte, net.Addr) (int, error)
	Read  func([]byte) (int, net.Addr, error)
	Close func() error
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

func newIPPacket(src, dest net.IP, protocol layers.IPProtocol) gopacket.NetworkLayer {
	if len(src) == net.IPv4len {
		return &layers.IPv4{
			Version:  4,
			Id:       uint16(rand.Intn(math.MaxInt16)),
			Flags:    layers.IPv4DontFragment,
			TTL:      uint8(rand.Intn(255) + 4),
			Protocol: protocol,
			SrcIP:    src,
			DstIP:    dest,
		}
	} else {
		return &layers.IPv6{
			Version:    4,
			NextHeader: protocol,
			SrcIP:      src,
			DstIP:      dest,
			HopByHop:   nil,
		}
	}
}

func (udp *UDP) Build(src, dest net.UDPAddr) []byte {
	buffer := newSerializeBuffer()
	ipPacket := newIPPacket(src.IP.To4(), dest.IP.To4(), layers.IPProtocolUDP)

	dport := layers.UDPPort(getValidPort(dest.Port))
	sport := layers.UDPPort(getValidPort(src.Port))

	udpLayer := &layers.UDP{
		SrcPort: sport,
		DstPort: dport,
	}

	if err := udpLayer.SetNetworkLayerForChecksum(ipPacket); err != nil {
		return nil
	}

	if udp.RandomizedPayloadLength > 0 {
		udp.Payload = RandomBytes(udp.RandomizedPayloadLength)
	}

	if err := gopacket.SerializeLayers(buffer, serializeOptions, ipPacket.(gopacket.SerializableLayer), udpLayer, gopacket.Payload(udp.Payload)); err != nil {
		return nil
	}

	return buffer.Bytes()
}

func (icmp *ICMP) Build(src, dest net.IPAddr) []byte {
	buffer := newSerializeBuffer()
	ipPacket := newIPPacket(src.IP.To4(), dest.IP.To4(), layers.IPProtocolICMPv4)
	icmpLayer := &layers.ICMPv4{
		TypeCode: icmp.Type,
		Id:       uint16(rand.Intn(math.MaxInt16)),
		Seq:      uint16(rand.Intn(math.MaxInt16)),
	}

	if icmp.RandomizedPayloadLength > 0 {
		icmp.Payload = RandomBytes(icmp.RandomizedPayloadLength)
	}

	layer := ipPacket.(gopacket.SerializableLayer)

	if icmp.Payload != nil {
		if err := gopacket.SerializeLayers(buffer, serializeOptions, layer, icmpLayer, gopacket.Payload(icmp.Payload)); err != nil {
			return nil
		}
	} else {
		if err := gopacket.SerializeLayers(buffer, serializeOptions, layer, icmpLayer); err != nil {
			return nil
		}
	}

	return buffer.Bytes()
}

func (tcp *TCP) Build(src, dest net.TCPAddr) []byte {
	buffer := newSerializeBuffer()
	ipPacket := newIPPacket(src.IP.To4(), dest.IP.To4(), layers.IPProtocolTCP)

	dport := layers.TCPPort(getValidPort(dest.Port))
	sport := layers.TCPPort(getValidPort(src.Port))

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

	if tcp.ACK && tcp.SYN { // For SYN-ACK flag
		tcpLayer.Options = append(tcpLayer.Options,
			layers.TCPOption{
				OptionType: layers.TCPOptionKindSACK,
			},
		)
	} else if tcp.SYN {
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
			OptionData:   RandomTimestamp(), // Fill with generated timestamp data
		}, layers.TCPOption{
			OptionType: layers.TCPOptionKindNop,
		}, layers.TCPOption{
			OptionType: layers.TCPOptionKindCCEcho,
		})
	} else if tcp.ACK { // For ACK flag
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
		timestamp := RandomTimestamp()
		tcpLayer.Options = append(tcpLayer.Options,
			layers.TCPOption{
				OptionType:   layers.TCPOptionKindTimestamps,
				OptionLength: uint8(len(timestamp)),
				OptionData:   timestamp, // Placeholder for timestamps
			},
		)
	}

	if tcp.Options != nil && len(tcp.Options) > 0 {
		tcpLayer.Options = append(tcpLayer.Options, tcp.Options...)
	}

	if tcp.Randomize {
		tcpLayer.Seq = uint32(rand.Intn(math.MaxInt16) + 1)
		tcpLayer.Window = uint16(rand.Intn(math.MaxInt16) + 1)
	}

	if err := tcpLayer.SetNetworkLayerForChecksum(ipPacket); err != nil {
		return nil
	}

	if tcp.Randomize {
		if tcp.RandomizedPayloadLength > 0 {
			tcp.Payload = RandomBytes(tcp.RandomizedPayloadLength)
		}
	}

	layer := ipPacket.(gopacket.SerializableLayer)

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
