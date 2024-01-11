//go:build windows

package RawSocket

import (
	"errors"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"math"
	"net"
	"strings"
	"sync"
	"time"
)

type ProtocolType int

//goland:noinspection GoUnusedGlobalVariable,GoSnakeCaseUsage
var (
	IPPROTO_TCP  = ProtocolType(0x1)
	IPPROTO_UDP  = ProtocolType(0x2)
	IPPROTO_ICMP = ProtocolType(0x3)
	IPPROTO_RAW  = ProtocolType(0x4)
	IPPROTO_IP   = ProtocolType(0x5)
)

var NetworkDevice *pcap.Interface
var SysSrcMac *net.HardwareAddr
var RouterMac *net.HardwareAddr

type PacketQueue struct {
	Packets   []gopacket.Packet
	MaxSize   int
	mx        *sync.Mutex
	broadcast *sync.Cond
}

func NewPacketQueue(maxSize int) *PacketQueue {
	return &PacketQueue{
		MaxSize:   maxSize,
		Packets:   make([]gopacket.Packet, 0, maxSize),
		broadcast: sync.NewCond(new(sync.Mutex)),
		mx:        new(sync.Mutex),
	}
}

func (q *PacketQueue) Add(packet gopacket.Packet) {
	q.broadcast.L.Lock()
	defer q.broadcast.L.Unlock()

	q.Packets = append(q.Packets, packet)
	if len(q.Packets) > q.MaxSize {
		q.Packets = q.Packets[1:]
	}

	q.broadcast.Signal()
}

func (q *PacketQueue) Poll() gopacket.Packet {
	q.mx.Lock()
	defer q.mx.Unlock()

	q.broadcast.L.Lock()
	defer q.broadcast.L.Unlock()

	for len(q.Packets) == 0 {
		q.broadcast.Wait()
	}

	packet := q.Packets[0]
	q.Packets = q.Packets[1:]

	return packet
}

func (q *PacketQueue) Len() int {
	q.mx.Lock()
	defer q.mx.Unlock()

	return len(q.Packets)
}

func (q *PacketQueue) Clear() {
	q.mx.Lock()
	defer q.mx.Unlock()

	q.Packets = make([]gopacket.Packet, 0, q.MaxSize)
}

func init() {
	SrcIP := GetSelfIP()
	devices, err := pcap.FindAllDevs()
	if err != nil {
		panic(err)
	}

	for _, dev := range devices {
		for _, address := range dev.Addresses {
			if address.IP.Equal(SrcIP) {
				NetworkDevice = &dev
				return
			}
		}
	}
	if NetworkDevice == nil {
		panic("Network device not found")
	}
}

func startSniffer(handle *pcap.Handle, receiver *PacketQueue) {
	defer func() {
		if err := recover(); err != nil {
			panic(err)
			receiver.Clear()
		}
	}()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for packet := range packetSource.Packets() {
		if IpLayer := packet.Layer(layers.LayerTypeIPv4); IpLayer != nil {
			if RouterMac == nil {
				if ArpLayer := packet.Layer(layers.LayerTypeEthernet); ArpLayer != nil {
					if IpLayer.(*layers.IPv4).SrcIP.Equal(GetSelfIP()) {
						ethernet := ArpLayer.(*layers.Ethernet)

						SysSrcMac = &ethernet.SrcMAC
						RouterMac = &ethernet.DstMAC
					}
				}
			}

			if !IpLayer.(*layers.IPv4).SrcIP.Equal(GetSelfIP()) {
				receiver.Add(packet)
			}
		}

	}
}

func OpenRawSocket(protocol ProtocolType) (*RawSocket, error) {
	var (
		handle *pcap.Handle
		err    error
	)

	handle, err = pcap.OpenLive(NetworkDevice.Name, math.MaxUint8, true, pcap.BlockForever)
	if err != nil {
		return nil, err
	}

	var receiver = NewPacketQueue(256)
	go startSniffer(handle, receiver)

	var ipRaw = false
	for SysSrcMac == nil {
		if err := updateMac(handle); err != nil {
			if strings.Contains(err.Error(), "mismatched hardware address sizes") {
				ipRaw = true
				break
			}
		}

		if SysSrcMac != nil {
			break
		}

		time.Sleep(1 * time.Second)
	}

	return &RawSocket{
		Write: func(bytes []byte, addr net.Addr) (int, error) {
			if addr == nil {
				return 0, errors.New("addr is nil")
			}

			if hasEthernet(bytes) && ipRaw {
				return 0, errors.New("ethernet is not supported in IPRaw mode")
			}

			if hasEthernet(bytes) {
				if err := handle.WritePacketData(bytes); err != nil {
					return 0, err
				}
				return len(bytes), nil
			}

			var packet gopacket.Packet

			if isIPv4(bytes) {
				packet = gopacket.NewPacket(bytes, layers.LayerTypeIPv4, decodeOptions)
			} else {
				packet = gopacket.NewPacket(bytes, layers.LayerTypeIPv6, decodeOptions)
			}

			layer3 := packet.NetworkLayer().(gopacket.SerializableLayer)
			layer4 := packet.TransportLayer().(gopacket.SerializableLayer)

			if tcp, ok := layer4.(*layers.TCP); ok {
				if err := tcp.SetNetworkLayerForChecksum(packet.NetworkLayer()); err != nil {
					return 0, err
				}
			} else if udp, ok := layer4.(*layers.UDP); ok {
				if err := udp.SetNetworkLayerForChecksum(packet.NetworkLayer()); err != nil {
					return 0, err
				}
			}

			buffer := gopacket.NewSerializeBuffer()

			if ipRaw {
				if err := gopacket.SerializeLayers(buffer, serializeOptions, layer3, layer4); err != nil {
					return 0, err
				}
			} else {
				if err := gopacket.SerializeLayers(buffer, serializeOptions, &layers.Ethernet{
					SrcMAC:       *SysSrcMac,
					DstMAC:       *RouterMac,
					EthernetType: layers.EthernetTypeIPv4,
				}, layer3, layer4); err != nil {
					return 0, err
				}
			}

			if err := handle.WritePacketData(buffer.Bytes()); err != nil {
				return 0, err
			}
			return len(bytes), nil
		},
		Read: func(bytes []byte) (int, net.Addr, error) {
			for {
				packet := receiver.Poll()

				if packet == nil {
					return 0, nil, errors.New("no packet available")
				}

				if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
					if protocol != IPPROTO_TCP && protocol != IPPROTO_RAW {
						continue
					}
				} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
					if protocol != IPPROTO_UDP && protocol != IPPROTO_RAW {
						continue
					}

				} else {
					if protocol != IPPROTO_ICMP && protocol != IPPROTO_RAW {
						continue
					}
				}

				var ipAddr net.IP

				if Ip4Layer := packet.Layer(layers.LayerTypeIPv4); Ip4Layer != nil {
					ipAddr = Ip4Layer.(*layers.IPv4).SrcIP
				} else if Ip6Layer := packet.Layer(layers.LayerTypeIPv6); Ip6Layer != nil {
					ipAddr = Ip6Layer.(*layers.IPv6).SrcIP
				}

				var data []byte

				switch protocol {
				case IPPROTO_UDP, IPPROTO_TCP:
					if transportLayer := packet.TransportLayer(); transportLayer != nil {
						data = append(transportLayer.LayerContents(), transportLayer.LayerPayload()...)
					}
				case IPPROTO_IP:
					if networkLayer := packet.NetworkLayer(); networkLayer != nil {
						data = networkLayer.LayerContents()
					}
				case IPPROTO_ICMP:
					if networkLayer := packet.NetworkLayer(); networkLayer != nil {
						data = append(networkLayer.LayerContents(), networkLayer.LayerPayload()...)
					}
				default:
					data = packet.Data()
				}

				copy(bytes, data)
				return len(data), &net.IPAddr{IP: ipAddr}, nil
			}
		},
		Close: func() error {
			handle.Close()
			return nil
		},
	}, nil
}

func isIPv4(bytes []byte) bool {
	return bytes[0] == 0x45
}

func updateMac(handle *pcap.Handle) error {
	if SysSrcMac != nil {
		return nil
	}

	mac, err := GetLocalMac()
	if err != nil {
		return err
	}

	targetMAC := net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	localIP := GetSelfIP()

	localMAC := mac
	arpPacket := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   localMAC,
		SourceProtAddress: localIP,
		DstHwAddress:      targetMAC,
		DstProtAddress:    GetSelfIP(),
	}
	ethernetPacket := &layers.Ethernet{
		SrcMAC:       localMAC,
		DstMAC:       targetMAC,
		EthernetType: layers.EthernetTypeARP,
	}

	buffer := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buffer, serializeOptions, ethernetPacket, arpPacket); err != nil {
		return err
	}

	if err := handle.WritePacketData(buffer.Bytes()); err != nil {
		return err
	}

	return nil
}

func GetLocalMac() (net.HardwareAddr, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	selfIp := GetSelfIP()

	for _, i := range interfaces {
		addrs, err := i.Addrs()
		if err != nil {
			return nil, err
		}

		for _, addr := range addrs {
			switch v := addr.(type) {
			case *net.IPAddr:
				if v.IP.Equal(selfIp) {
					return i.HardwareAddr, nil
				}
			case *net.IPNet:
				if v.IP.Equal(selfIp) {
					return i.HardwareAddr, nil
				}
			}
		}
	}

	return nil, fmt.Errorf("failed to retrieve local MAC address")
}

func hasEthernet(bytes []byte) bool {
	return bytes[0] == 0x08 && bytes[1] == 0x00
}
