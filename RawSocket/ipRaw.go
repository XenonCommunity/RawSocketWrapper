package RawSocket

import (
	"net"
	"strings"
	"time"
)

func getIfaceIP() net.IP {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}

	for _, i := range ifaces {
		if i.Flags&net.FlagUp != 0 || i.Flags&net.FlagLoopback != 0 {
			continue
		}

		addrs, err := i.Addrs()
		if err != nil {
			continue
		}

		for _, a := range addrs {
			switch v := a.(type) {
			case *net.IPAddr:
				if v.IP.IsLoopback() || v.IP.To4() == nil {
					continue
				}
				return v.IP

			case *net.IPNet:
				if v.IP.IsLoopback() || v.IP.To4() == nil {
					continue
				}
				return v.IP
			}
		}
	}

	return nil
}

func requestIP() net.IP {
	conn, err := net.DialTimeout("tcp", "8.8.8.8:443", time.Second)

	if err == nil {
		defer conn.Close()
		if _, err := conn.Write([]byte(
			"HEAD /?amongus HTTP/1.1\r\n" +
				"Host: one.one.one.one\r\n" +
				"Connection: Close\r\n\r\n")); err == nil {
			return net.ParseIP(strings.Split(conn.LocalAddr().String(), ":")[0])
		}
	}

	return nil
}

var selfIP net.IP

func GetSelfIP() net.IP {
	if selfIP != nil {
		return selfIP
	}

	selfIP = requestIP()
	if selfIP == nil {
		selfIP = getIfaceIP()
	}

	return selfIP
}
