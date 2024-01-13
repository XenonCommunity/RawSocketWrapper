package RawSocket

import (
	"net"
	"strings"
)

type netContainer struct {
	start, end net.IP
}

// IPIterator represents an iterator over a collection of IP addresses.
type IPIterator struct {
	containers []netContainer
	currentIdx int
	currentIP  net.IP
	skipLocal  bool
}

// ToIPIterator creates a new instance of IPIterator with the given data.
func ToIPIterator(data ...string) *IPIterator {
	return &IPIterator{
		containers: parseData(data),
	}
}

// parseData parses a slice of strings and returns a slice of netContainers.
func parseData(data []string) []netContainer {
	var pars []netContainer

	for _, x := range data {
		if strings.Contains(x, "-") {
			// If the string contains a "-", split it into two parts.
			n := strings.SplitN(x, "-", 2)

			// Parse the start and end IP addresses.
			start := net.ParseIP(n[0])
			end := net.ParseIP(n[1])

			// Append the netContainer to the pars slice.
			pars = append(pars, netContainer{start: start, end: end})
			continue
		}

		// If the string is not in the format "x.x.x.x/y", skip it.
		start, end, err := cidrStartEnd(x)
		if err != nil {
			continue
		}

		// Append the netContainer to the pars slice.
		pars = append(pars, netContainer{start: start, end: end})
	}

	return pars
}

// cidrStartEnd returns the start and end IP addresses of a given CIDR range.
func cidrStartEnd(cidr string) (net.IP, net.IP, error) {
	// Parse the CIDR string into an IPNet object.
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, nil, err
	}

	// Calculate the start IP address by masking the IP address with the network mask.
	startIP := ipNet.IP.Mask(ipNet.Mask)

	// Create a copy of the start IP address to use as the end IP address.
	endIP := make(net.IP, len(startIP))
	copy(endIP, startIP)

	// Calculate the end IP address by performing a bitwise OR operation on each byte of the IP address
	// with the bitwise complement of the corresponding byte in the network mask.
	for i := range endIP {
		endIP[i] |= ^ipNet.Mask[i]
	}

	return startIP, endIP, nil
}

// Next returns the next IP in the iterator.
func (it *IPIterator) Next() net.IP {
	// If at the start of the iterator, reset the iterator.
	if it.atStart() {
		it.resetIterator()
	}

	cont := it.currentContainer()

	// If at the end of the current container, move to the next container.
	if it.atEndOfContainer(cont) {
		return it.moveToNextContainer()
	}

	// If the current IP is valid within the container's range, return it.
	if it.isValidIPInRange(cont) {
		return it.getNextIP(cont)
	}

	// If no valid IP is found, return nil.
	return nil
}

// atStart checks if the iterator is at the start position.
// Returns true if the iterator is at the start, false otherwise.
func (it *IPIterator) atStart() bool {
	// Check if the current index is -1 or if the current IP is nil.
	return it.currentIdx == -1 || it.currentIP == nil
}

// resetIterator resets the iterator to its initial state.
// This function sets the current index to 0 and the current IP to the start IP of the first container.
func (it *IPIterator) resetIterator() {
	it.currentIdx = 0
	it.currentIP = it.containers[0].start
}

// currentContainer returns the current netContainer object that the iterator is pointing to.
func (it *IPIterator) currentContainer() netContainer {
	return it.containers[it.currentIdx]
}

// atEndOfContainer checks if the iterator is at the end of the container.
func (it *IPIterator) atEndOfContainer(cont netContainer) bool {
	return it.currentIP.Equal(cont.end)
}

// moveToNextContainer moves the iterator to the next container and returns the next IP address.
func (it *IPIterator) moveToNextContainer() net.IP {
	// Increment the current index
	it.currentIdx++

	// Check if the current index is out of bounds
	if it.currentIdx >= len(it.containers) {
		return nil
	}

	// Set the current IP to the start IP of the next container
	it.currentIP = it.containers[it.currentIdx].start

	// Return the end IP of the previous container
	return it.containers[it.currentIdx-1].end
}

// isValidIPInRange checks if the current IP address in the iterator is within the range of a given network container.
// It returns true if the current IP is less than or equal to the end IP of the container, otherwise false.
func (it *IPIterator) isValidIPInRange(cont netContainer) bool {
	return ipLessOrEqual(it.currentIP, cont.end)
}

// getNextIP returns the next available IP address from the iterator.
// If skipLocal is true, it skips local addresses.
func (it *IPIterator) getNextIP(cont netContainer) net.IP {
	it.incrementIP()

	if !it.skipLocal {
		return it.currentIP
	}

	return it.skipLocalAddresses(cont)
}

// incrementIP increments the currentIP of the IPIterator.
func (it *IPIterator) incrementIP() {
	it.currentIP = incIP(it.currentIP)
}

// skipLocalAddresses skips any local addresses in the IPIterators container
func (it *IPIterator) skipLocalAddresses(cont netContainer) net.IP {
	// Iterate until a non-local address is found
	for it.isLocalAddress() {
		// If the iterator is at the end of the container, return nil
		if it.atEndOfContainer(cont) {
			return nil
		}
		// Increment the IP address
		it.incrementIP()
	}
	// Return the current IP address
	return it.currentIP
}

// isLocalAddress checks if the current IP address is a local address.
// It returns true if the IP address is local, and false otherwise.
func (it *IPIterator) isLocalAddress() bool {
	// Check if the first octet of the IP address is within the range of local addresses.
	if it.currentIP[0] == 10 || it.currentIP[0] == 127 ||
		it.currentIP[0] == 0 || it.currentIP[0] == 172 {
		return true
	}

	// Check if the IP address is unspecified, loopback, or private.
	if it.currentIP.IsUnspecified() || it.currentIP.IsLoopback() ||
		it.currentIP.IsPrivate() {
		return true
	}

	return false
}

// ipLessOrEqual checks if IP address ip is less than or equal to IP address ip2.
// It compares the IP address byte by byte and returns true if ip is less than or equal to ip2,
// and false otherwise.
func ipLessOrEqual(ip, ip2 net.IP) bool {
	for i := range ip {
		if ip[i] < ip2[i] {
			return true
		} else if ip[i] > ip2[i] {
			return false
		}
	}
	return true
}

// HasNext returns true if there is a next IP address in the iterator.
func (it *IPIterator) HasNext() bool {
	// If the current index is negative or the current IP address is nil, there is a next IP address.
	if it.currentIdx < 0 || it.currentIP == nil {
		return true
	}

	// If the current index is greater than or equal to the number of containers, there is no next IP address.
	if it.currentIdx >= len(it.containers) {
		return false
	}

	// Get the current container.
	container := it.containers[it.currentIdx]

	// If the current IP address is equal to the end IP address of the container, move to the next container.
	if it.currentIP.Equal(container.end) {
		it.moveToNextContainer()
		return it.currentIdx < len(it.containers)
	}

	// There is a next IP address.
	return true
}

// SetSkipLocal sets the skipLocal flag to the given value.
func (it *IPIterator) SetSkipLocal(b bool) {
	it.skipLocal = b
}

// incIP increments the given IP address by one.
// It returns the incremented IP address.
func incIP(ip net.IP) net.IP {
	// Create a new IP address with the same length as the input IP address.
	incIP := make(net.IP, len(ip))

	// Copy the input IP address to the new IP address.
	copy(incIP, ip)

	// Increment each byte of the IP address starting from the last byte.
	for j := len(incIP) - 1; j >= 0; j-- {
		incIP[j]++

		// If the incremented byte is greater than 0, there is no need to carry over the increment.
		// Break the loop and return the incremented IP address.
		if incIP[j] > 0 {
			break
		}
	}

	return incIP
}
