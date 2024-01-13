//go:build windows

package RawSocket

import (
	"errors"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
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

// NewPacketQueue returns a new instance of PacketQueue with the given max size.
func NewPacketQueue(maxSize int) *PacketQueue {
	// Create a new PacketQueue object with the specified max size and initialize its fields.
	return &PacketQueue{
		MaxSize:   maxSize,
		Packets:   make([]gopacket.Packet, 0, maxSize),
		broadcast: sync.NewCond(new(sync.Mutex)),
		mx:        new(sync.Mutex),
	}
}

// Add adds a packet to the PacketQueue.
func (q *PacketQueue) Add(packet gopacket.Packet) {
	// Acquire the lock to ensure exclusive access to the queue.
	q.broadcast.L.Lock()
	defer q.broadcast.L.Unlock()

	// Add the packet to the queue.
	q.Packets = append(q.Packets, packet)

	// If the queue exceeds the maximum size, remove the oldest packet.
	if len(q.Packets) > q.MaxSize {
		q.Packets = q.Packets[1:]
	}

	// Signal that a new packet has been added to the queue.
	q.broadcast.Signal()
}

// Poll removes and returns the next packet from the packet queue.
// If the queue is empty, it waits for a packet to be added to the queue.
func (q *PacketQueue) Poll() gopacket.Packet {
	q.mx.Lock()
	defer q.mx.Unlock()

	q.broadcast.L.Lock()
	defer q.broadcast.L.Unlock()

	// Wait for a packet to be added to the queue
	for len(q.Packets) == 0 {
		q.broadcast.Wait()
	}

	// Get the first packet in the queue
	packet := q.Packets[0]
	q.Packets = q.Packets[1:]

	return packet
}

// Len returns the length of the PacketQueue.
func (q *PacketQueue) Len() int {
	// Lock the mutex to ensure exclusive access to the PacketQueue.
	q.mx.Lock()
	defer q.mx.Unlock()

	// Return the length of the PacketQueue.
	return len(q.Packets)
}

// Clear removes all packets from the packet queue.
func (q *PacketQueue) Clear() {
	// Acquire the lock to ensure exclusive access to the packet queue.
	q.mx.Lock()
	defer q.mx.Unlock()

	// Create a new empty slice of packets with the same capacity as the original slice.
	q.Packets = make([]gopacket.Packet, 0, q.MaxSize)
}

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

// startSniffer starts the packet sniffer using the provided handle and adds packets to the receiver queue.
// If an error occurs during packet processing, it recovers and clears the receiver queue before re-throwing the error.
func startSniffer(handle *pcap.Handle, receiver *PacketQueue) {
	// Recover from any panics and clear the receiver queue before re-throwing the error
	defer func() {
		if err := recover(); err != nil {
			receiver.Clear()
			panic(err)
		}
	}()

	// Create a packet source from the handle
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	// Process each packet from the packet source
	for packet := range packetSource.Packets() {
		// Check if the packet has an IPv4 layer
		if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
			// Check if RouterMac is not set
			if RouterMac == nil {
				// Check if the packet has an Ethernet layer
				if ethernetLayer := packet.Layer(layers.LayerTypeEthernet); ethernetLayer != nil {
					// Check if the source IP of the packet is equal to GetSelfIP()
					if ipLayer.(*layers.IPv4).SrcIP.Equal(GetSelfIP()) {
						ethernet := ethernetLayer.(*layers.Ethernet)

						SysSrcMac = &ethernet.SrcMAC
						RouterMac = &ethernet.DstMAC
					}
				}
			}

			// Check if the source IP of the packet is not equal to GetSelfIP()
			if !ipLayer.(*layers.IPv4).SrcIP.Equal(GetSelfIP()) {
				receiver.Add(packet)
			}
		}
	}
}

type PcapSocket struct {
	isRaw    bool
	handle   *pcap.Handle
	receiver *PacketQueue
	protocol ProtocolType
}

// newPcapSocket creates a new PcapSocket with the given parameters.
func newPcapSocket(isRaw bool, handle *pcap.Handle, receiver *PacketQueue, protocol ProtocolType) *PcapSocket {
	return &PcapSocket{
		isRaw:    isRaw,
		handle:   handle,
		receiver: receiver,
		protocol: protocol,
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
		if err := p.handle.WritePacketData(bytes); err != nil {
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
	if err := p.handle.WritePacketData(buffer.Bytes()); err != nil {
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

// Read reads packets from the pcap socket and copies the data to the provided byte slice.
// It returns the number of bytes read, the source address of the packet, and any error encountered.
func (p *PcapSocket) Read(bytes []byte) (int, net.Addr, error) {
	for {
		packet := p.receiver.Poll()

		if packet == nil {
			return 0, nil, errors.New("no packet available")
		}

		switch p.protocol {
		case IPPROTO_TCP:
			// Skip packets that are not TCP
			if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer == nil {
				continue
			}
		case IPPROTO_UDP:
			// Skip packets that are not UDP
			if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer == nil {
				continue
			}
		default:
			// Skip packets that are not TCP, UDP, or Raw
			if p.protocol != IPPROTO_RAW {
				continue
			}
		}

		var ipAddr net.IP

		switch packet := packet.(type) {
		case gopacket.Packet:
			if Ip4Layer := packet.Layer(layers.LayerTypeIPv4); Ip4Layer != nil {
				// Get the source IP address from IPv4 packet
				ipAddr = Ip4Layer.(*layers.IPv4).SrcIP
			} else if Ip6Layer := packet.Layer(layers.LayerTypeIPv6); Ip6Layer != nil {
				// Get the source IP address from IPv6 packet
				ipAddr = Ip6Layer.(*layers.IPv6).SrcIP
			}
		}

		var data []byte

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
}

// Close closes the PcapSocket by closing the underlying handle.
// It returns an error if there was a problem closing the handle.
func (p *PcapSocket) Close() error {
	p.handle.Close()
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

	// Create a packet queue to store received packets.
	receiver := NewPacketQueue(256)

	// Start a goroutine to capture packets and enqueue them into the receiver queue.
	go startSniffer(handle, receiver)

	// Flag to determine if IP raw mode is needed.
	var ipRaw bool

	// Loop until the source MAC address is updated.
	for SysSrcMac == nil {
		// Update the MAC address.
		if err := updateMac(handle); err != nil {
			// If the error indicates mismatched hardware address sizes, set the IP raw flag.
			if strings.Contains(err.Error(), "mismatched hardware address sizes") {
				ipRaw = true
				break
			}
			// Panic if there is any other error.
			panic(err)
		}

		// Exit the loop if the MAC address is updated.
		if SysSrcMac != nil {
			break
		}

		// Sleep for 1 second and try again.
		time.Sleep(1 * time.Second)
	}

	// Create a new PcapSocket with the necessary parameters.
	return newPcapSocket(ipRaw, handle, receiver, protocol), nil
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
