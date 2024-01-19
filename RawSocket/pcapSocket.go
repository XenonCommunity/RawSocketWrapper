//go:build windows

package RawSocket

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"

	"errors"
	"fmt"
	"net"
	"strings"
	"syscall"
)

var NoPacketAvailableErr = errors.New("no packet available")

//goland:noinspection GoUnusedGlobalVariable,GoSnakeCaseUsage
var (
	IPPROTO_TCP  = ProtocolType(syscall.IPPROTO_TCP)
	IPPROTO_UDP  = ProtocolType(syscall.IPPROTO_UDP)
	IPPROTO_ICMP = ProtocolType(0x1)
	IPPROTO_RAW  = ProtocolType(0xFF)
	IPPROTO_IP   = ProtocolType(syscall.IPPROTO_IP)
)

var NetworkDevice *pcap.Interface
var SysSrcMac *net.HardwareAddr
var RouterMac *net.HardwareAddr

// init initializes the network device.
func init() {
	// Get the IP address of the current machine
	SrcIP := GetSelfIP()

	// Find all available network devices
	devices, err := pcap.FindAllDevs()
	if err != nil {
		panic(err)
	}

	// Iterate through each network device
	for _, dev := range devices {
		// Iterate through each IP address associated with the device
		for _, address := range dev.Addresses {
			// Check if the IP address matches the source IP address
			if address.IP.Equal(SrcIP) {
				// Set the network device to the matching device and return
				NetworkDevice = &dev
				return
			}
		}
	}

	// If no network device was found, panic with an error message
	if NetworkDevice == nil {
		panic("Network device not found")
	}
}

// waitForMac waits for a packet that contains the MAC address of the router.
// It takes a pcap.Handle as input and returns nothing.
// The function processes each packet from the packet source until it finds a packet with the MAC address.
func waitForMac(packetSource *gopacket.PacketSource) {
	// Get the IP address of the current device
	ip := GetSelfIP()

	// Process each packet from the packet source
	for {
		packet, err := packetSource.NextPacket()
		if err != nil {
			return
		}

		// Check if the packet has an IPv4 layer
		if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
			// Check if RouterMac is not set
			if RouterMac == nil {
				// Check if the packet has an Ethernet layer
				if ethernetLayer := packet.Layer(layers.LayerTypeEthernet); ethernetLayer != nil {
					// Check if the source IP of the packet is equal to GetSelfIP()
					if ipLayer.(*layers.IPv4).SrcIP.Equal(ip) {
						ethernet := ethernetLayer.(*layers.Ethernet)

						// Set the source MAC address and the router MAC address
						SysSrcMac = &ethernet.SrcMAC
						RouterMac = &ethernet.DstMAC
						return
					}
				}
			}
		}
	}
}

type PcapSocket struct {
	*pcap.Handle
	isRaw    bool
	protocol ProtocolType
	source   *gopacket.PacketSource
}

// newPcapSocket creates a new PcapSocket with the given parameters.
func newPcapSocket(isRaw bool, handle *pcap.Handle, protocol ProtocolType, source *gopacket.PacketSource) *PcapSocket {
	return &PcapSocket{
		isRaw:    isRaw,
		Handle:   handle,
		protocol: protocol,
		source:   source,
	}
}

// Write writes the given bytes to the PcapSocket and returns the number of bytes written.
// If addr is nil, it returns an error indicating that the address is nil.
// If the bytes contain an Ethernet header and the PcapSocket is in IPRaw mode, it returns an error indicating that Ethernet is not supported in IPRaw mode.
// If the bytes contain an Ethernet header, it writes the packet data to the handle and returns the number of bytes written.
// If the bytes do not contain an Ethernet header, it creates a packet, extracts the network and transport layers from the packet, sets the network layer for checksum calculation if the transport layer is TCP or UDP, creates a serialize buffer, writes the buffer data to the handle, and returns the number of bytes written.
func (p *PcapSocket) Write(bytes []byte, addr net.Addr) (int, error) {
	// Check if addr is nil
	if addr == nil {
		return 0, errors.New("addr is nil")
	}

	// Check if Ethernet is not supported in IPRaw mode
	if hasEthernet(bytes) && p.isRaw {
		return 0, errors.New("ethernet is not supported in IPRaw mode")
	}

	// Write the packet data if the bytes contain an Ethernet header
	if hasEthernet(bytes) {
		if err := p.WritePacketData(bytes); err != nil {
			return 0, err
		}
		return len(bytes), nil
	}

	// Create a packet and get the network and transport layers
	packet := createPacket(bytes)
	layer3, layer4 := getNetworkAndTransportLayers(packet)

	// Set the network layer for checksum calculation if the transport layer is TCP or UDP
	if tcp, ok := layer4.(*layers.TCP); ok {
		if err := tcp.SetNetworkLayerForChecksum(packet.NetworkLayer()); err != nil {
			return 0, err
		}
	} else if udp, ok := layer4.(*layers.UDP); ok {
		if err := udp.SetNetworkLayerForChecksum(packet.NetworkLayer()); err != nil {
			return 0, err
		}
	}

	// Create a serialize buffer and write the buffer data to the handle
	buffer := createSerializeBuffer(p.isRaw, layer3, layer4)
	if err := p.WritePacketData(buffer.Bytes()); err != nil {
		return 0, err
	}

	return len(bytes), nil
}

// createPacket creates a gopacket.Packet from the given bytes.
// It checks if the bytes represent an IPv4 packet, and if so,
// creates the packet with the IPv4 layer type. Otherwise, it
// creates the packet with the IPv6 layer type.
func createPacket(bytes []byte) gopacket.Packet {
	if isIPv4(bytes) {
		return gopacket.NewPacket(bytes, layers.LayerTypeIPv4, decodeOptions)
	}
	return gopacket.NewPacket(bytes, layers.LayerTypeIPv6, decodeOptions)
}

// getNetworkAndTransportLayers returns the network and transport layers of a packet as serializable layers.
func getNetworkAndTransportLayers(packet gopacket.Packet) (gopacket.SerializableLayer, gopacket.SerializableLayer) {
	// Retrieve the network layer and assert it as a serializable layer
	layer3 := packet.NetworkLayer().(gopacket.SerializableLayer)

	// Retrieve the transport layer and assert it as a serializable layer
	layer4 := packet.TransportLayer().(gopacket.SerializableLayer)

	// Return the network and transport layers
	return layer3, layer4
}

// createSerializeBuffer creates a serialize buffer based on the given parameters.
// If isRaw is true, it serializes layer3 and layer4 into the buffer.
// If isRaw is false, it serializes layer3, layer4, and an Ethernet layer with source and destination MAC addresses and Ethernet type IPv4.
// It returns the serialize buffer.
func createSerializeBuffer(isRaw bool, layer3, layer4 gopacket.SerializableLayer) gopacket.SerializeBuffer {
	buffer := gopacket.NewSerializeBuffer()

	if isRaw {
		if err := gopacket.SerializeLayers(buffer, serializeOptions, layer3, layer4); err != nil {
			return nil
		}
	} else {
		if err := gopacket.SerializeLayers(buffer, serializeOptions, &layers.Ethernet{
			SrcMAC:       *SysSrcMac,
			DstMAC:       *RouterMac,
			EthernetType: layers.EthernetTypeIPv4,
		}, layer3, layer4); err != nil {
			return nil
		}
	}

	return buffer
}

// NextPacket returns the next packet from the PcapSocket.
func (p *PcapSocket) NextPacket() (gopacket.Packet, error) {
	return p.source.NextPacket()
}

func (p *PcapSocket) Iter() chan gopacket.Packet {
	// Create a buffered channel with a capacity of 1024.
	packets := make(chan gopacket.Packet, 1024)
	// Start a goroutine that will call the startIter method and pass the packets channel.
	go p.startIter(packets)
	// Return the packets channel.
	return packets
}

// startIter starts iterating over packets from the PcapSocket and sends them to the provided channel.
func (p *PcapSocket) startIter(packets chan gopacket.Packet) {
	defer func() {
		_ = recover()
	}()

	// Continuously read packets from the PcapSocket until the channel is closed.
	for packets != nil {
		// Get the next packet from the PcapSocket.
		packet, err := p.NextPacket()
		if err != nil {
			continue
		}

		// Send the packet to the packets channel.
		packets <- packet
	}
}

// Read reads bytes from the packet socket and returns the number of bytes read,
// the source address of the packet, and any error encountered.
// It uses the provided byte slice to copy the data read from the packet.
func (p *PcapSocket) Read(bytes []byte) (int, net.Addr, error) {
	// Iterate over packets received from the source
	for {
		packet, err := p.source.NextPacket()
		if err != nil {
			return 0, nil, err
		}

		var ipAddr net.IP

		// Extract the source IP address from the packet
		if Ip4Layer := packet.Layer(layers.LayerTypeIPv4); Ip4Layer != nil {
			ipAddr = Ip4Layer.(*layers.IPv4).SrcIP
		} else if Ip6Layer := packet.Layer(layers.LayerTypeIPv6); Ip6Layer != nil {
			ipAddr = Ip6Layer.(*layers.IPv6).SrcIP
		}

		// Check if the packet matches the specified protocol
		switch p.protocol {
		case IPPROTO_TCP:
			if packet.Layer(layers.LayerTypeTCP) == nil {
				continue
			}
		case IPPROTO_UDP:
			if packet.Layer(layers.LayerTypeUDP) == nil {
				continue
			}
		case IPPROTO_IP:
			if packet.Layer(layers.LayerTypeIPv4) == nil || packet.Layer(layers.LayerTypeIPv6) == nil {
				continue
			}
		case IPPROTO_ICMP:
			if packet.Layer(layers.LayerTypeICMPv4) == nil || packet.Layer(layers.LayerTypeICMPv6) == nil {
				continue
			}
		default:
			if p.protocol != IPPROTO_RAW {
				continue
			}
		}

		var data []byte

		// Extract the data from the packet based on the specified protocol
		switch p.protocol {
		case IPPROTO_UDP, IPPROTO_TCP:
			// Get the transport layer data for UDP or TCP packets
			if transportLayer := packet.TransportLayer(); transportLayer != nil {
				data = append(transportLayer.LayerContents(), transportLayer.LayerPayload()...)
			}
		case IPPROTO_IP:
			// Get the network layer data for IP packets
			if networkLayer := packet.NetworkLayer(); networkLayer != nil {
				data = networkLayer.LayerContents()
			}
		case IPPROTO_ICMP:
			// Get the network layer data for ICMP packets
			if networkLayer := packet.NetworkLayer(); networkLayer != nil {
				data = append(networkLayer.LayerContents(), networkLayer.LayerPayload()...)
			}
		default:
			// Get the raw packet data for other protocols
			data = packet.Data()
		}

		// Copy the data to the provided byte slice
		copy(bytes, data)
		return len(data), &net.IPAddr{IP: ipAddr}, nil
	}

	// If no packet is available, return an error
	return 0, nil, NoPacketAvailableErr
}

// Close closes the PcapSocket by closing the underlying handle.
// It returns an error if there was a problem closing the handle.
func (p *PcapSocket) Close() error {
	p.Handle.Close()
	return nil
}

// OpenRawSocket opens a raw socket for the given protocol.
// It returns a PcapSocket and an error, if any.
func OpenRawSocket(protocol ProtocolType) (RawSocket, error) {
	// Open a live capture on the network device with a maximum packet length of 255 bytes.
	handle, err := pcap.OpenLive(NetworkDevice.Name, 255, true, pcap.BlockForever)
	if err != nil {
		return nil, err
	}

	// Flag to determine if IP raw mode is needed.
	var ipRaw bool

	// Update the MAC address.
	if err := updateMac(handle); err != nil {
		if strings.Contains(err.Error(), "mismatched hardware address sizes") {
			ipRaw = true
		}
		// Panic if there is any other error.
		panic(err)
	}

	source := gopacket.NewPacketSource(handle, handle.LinkType())
	source.NoCopy = true
	source.DecodeOptions = decodeOptions

	waitForMac(source)

	// Create a new PcapSocket with the necessary parameters.
	return newPcapSocket(ipRaw, handle, protocol, source), nil
}

// isIPv4 checks if the given byte slice represents an IPv4 address.
func isIPv4(bytes []byte) bool {
	// Check if the first byte is equal to 0x45, which represents the version number and header length in an IPv4 packet.
	return bytes[0] == 0x45
}

// updateMac updates the MAC address of the network interface used by the pcap handle.
// It sends an ARP request packet to retrieve the MAC address and updates the handle's MAC address if successful.
func updateMac(handle *pcap.Handle) error {
	// If the MAC address is already set, no need to update it.
	if SysSrcMac != nil {
		return nil
	}

	// Get the local MAC address.
	localMAC, err := GetLocalMac()
	if err != nil {
		return err
	}

	// Create an ARP packet with the necessary fields.
	arpPacket := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   localMAC,
		SourceProtAddress: GetSelfIP(),
		DstHwAddress:      net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		DstProtAddress:    GetSelfIP(),
	}

	// Create an Ethernet packet with the ARP packet as payload.
	ethernetPacket := &layers.Ethernet{
		SrcMAC:       localMAC,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}

	// Serialize the Ethernet and ARP packets into a buffer.
	buffer := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buffer, serializeOptions, ethernetPacket, arpPacket); err != nil {
		return err
	}

	// Write the buffer to the pcap handle to send the packet.
	if err := handle.WritePacketData(buffer.Bytes()); err != nil {
		return err
	}

	return nil
}

// GetLocalMac retrieves the local MAC address.
func GetLocalMac() (net.HardwareAddr, error) {
	// Get all network interfaces
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	// Get the IP address of the current machine
	selfIP := GetSelfIP()

	// Iterate through each network interface
	for _, iface := range interfaces {
		// Get the list of addresses associated with the interface
		addrs, err := iface.Addrs()
		if err != nil {
			return nil, err
		}

		// Check if any of the addresses match the IP of the current machine
		for _, addr := range addrs {
			if isSameIP(addr, selfIP) {
				return iface.HardwareAddr, nil
			}
		}
	}

	return nil, fmt.Errorf("failed to retrieve local MAC address")
}

// isSameIP checks if the given network address is the same as the self IP.
//
// If the network address is of type *net.IPAddr or *net.IPNet,
// it compares the IP of the address with the self IP and returns true if they are equal.
// Otherwise, it returns false.
func isSameIP(addr net.Addr, selfIP net.IP) bool {
	switch v := addr.(type) {
	case *net.IPAddr:
		return v.IP.Equal(selfIP)
	case *net.IPNet:
		return v.IP.Equal(selfIP)
	}

	return false
}

// hasEthernet checks if the given byte slice represents an Ethernet frame.
func hasEthernet(bytes []byte) bool {
	// Check if the first byte is 0x08 and the second byte is 0x00.
	return bytes[0] == 0x08 && bytes[1] == 0x00
}
