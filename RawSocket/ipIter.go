package RawSocket

import (
	"net"
	"strings"
)

type netContainer struct {
	start, end net.IP
}

type IPIterator struct {
	containers []netContainer
	currentIdx int
	currentIP  net.IP
	skipLocal  bool
}

func ToIPIterator(data ...string) *IPIterator {
	return &IPIterator{
		containers: parseData(data),
	}
}

func parseData(data []string) []netContainer {
	var pars []netContainer

	for _, x := range data {
		if strings.Contains(x, "-") {
			n := strings.SplitN(x, "-", 2)

			start := net.ParseIP(n[0])
			end := net.ParseIP(n[1])

			pars = append(pars, netContainer{start: start, end: end})
			continue
		}

		start, end, err := cidrStartEnd(x)
		if err != nil {
			continue
		}

		pars = append(pars, netContainer{start: start, end: end})
	}

	return pars
}

func cidrStartEnd(cidr string) (net.IP, net.IP, error) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, nil, err
	}

	startIP := ipNet.IP.Mask(ipNet.Mask)
	endIP := make(net.IP, len(startIP))
	copy(endIP, startIP)
	for i := range endIP {
		endIP[i] |= ^ipNet.Mask[i]
	}

	return startIP, endIP, nil
}

func NewIPIterator(containers []netContainer) *IPIterator {
	return &IPIterator{
		containers: containers,
		currentIdx: -1,
		currentIP:  nil,
	}
}

func (it *IPIterator) Next() net.IP {
	if it.atStart() {
		it.resetIterator()
	}

	cont := it.currentContainer()

	if it.atEndOfContainer(cont) {
		return it.moveToNextContainer()
	}

	if it.isValidIPInRange(cont) {
		return it.getNextIP(cont)
	}

	return nil
}

func (it *IPIterator) atStart() bool {
	return it.currentIdx == -1 || it.currentIP == nil
}

func (it *IPIterator) resetIterator() {
	it.currentIdx = 0
	it.currentIP = it.containers[0].start
}

func (it *IPIterator) currentContainer() netContainer {
	return it.containers[it.currentIdx]
}

func (it *IPIterator) atEndOfContainer(cont netContainer) bool {
	return it.currentIP.Equal(cont.end)
}

func (it *IPIterator) moveToNextContainer() net.IP {
	it.currentIdx++
	if it.currentIdx >= len(it.containers) {
		return nil
	}
	it.currentIP = it.containers[it.currentIdx].start
	return it.containers[it.currentIdx-1].end
}

func (it *IPIterator) isValidIPInRange(cont netContainer) bool {
	return ipLessOrEqual(it.currentIP, cont.end)
}

func (it *IPIterator) getNextIP(cont netContainer) net.IP {
	it.incrementIP()

	if !it.skipLocal {
		return it.currentIP
	}

	return it.skipLocalAddresses(cont)
}

func (it *IPIterator) incrementIP() {
	it.currentIP = incIP(it.currentIP)
}

func (it *IPIterator) skipLocalAddresses(cont netContainer) net.IP {
	for it.isLocalAddress() {
		if it.atEndOfContainer(cont) {
			return nil
		}
		it.incrementIP()
	}
	return it.currentIP
}

func (it *IPIterator) isLocalAddress() bool {
	return it.currentIP[0] == 10 || it.currentIP[0] == 127 ||
		it.currentIP[0] == 0 || it.currentIP[0] == 172 ||
		it.currentIP.IsUnspecified() || it.currentIP.IsLoopback() ||
		it.currentIP.IsPrivate()
}
func ipLessOrEqual(a, b net.IP) bool {
	for i := range a {
		if a[i] < b[i] {
			return true
		} else if a[i] > b[i] {
			return false
		}
	}
	return true
}

func (it *IPIterator) HasNext() bool {
	if it.currentIdx < 0 || it.currentIP == nil {
		return true
	}

	if it.currentIdx >= len(it.containers) {
		return false
	}

	container := it.containers[it.currentIdx]
	if it.currentIP.Equal(container.end) {
		it.moveToNextContainer()
		return it.currentIdx < len(it.containers)
	}

	return true
}

func (it *IPIterator) SetSkipLocal(b bool) {
	it.skipLocal = b
}

func incIP(ip net.IP) net.IP {
	incIP := make(net.IP, len(ip))
	copy(incIP, ip)
	for j := len(incIP) - 1; j >= 0; j-- {
		incIP[j]++
		if incIP[j] > 0 {
			break
		}
	}
	return incIP
}
