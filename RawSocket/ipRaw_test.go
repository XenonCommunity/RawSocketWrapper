package RawSocket

import "testing"

func TestGetSelfIP(t *testing.T) {
	t.Log(GetSelfIP())
}

func TestGetInterfaceByIP(t *testing.T) {
	t.Log(getInterfaceByIP(GetSelfIP()))
}
