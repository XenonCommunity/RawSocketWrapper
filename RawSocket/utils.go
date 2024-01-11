package RawSocket

import (
	"math"
	"math/rand"
	"time"
)

func getValidPort(port int) int {
	if port <= 0 {
		return rand.Intn(math.MaxInt8) + 1
	}
	return port
}

func RandomTimestamp() []byte {
	val := uint32(time.Now().UnixNano())
	secr := uint32(0)

	timestampData := make([]byte, 8)
	timestampData[0] = byte(val >> 24)
	timestampData[1] = byte(val >> 16)
	timestampData[2] = byte(val >> 8)
	timestampData[3] = byte(val)
	timestampData[4] = byte(secr >> 24)
	timestampData[5] = byte(secr >> 16)
	timestampData[6] = byte(secr >> 8)
	timestampData[7] = byte(secr)

	return timestampData
}

func RandomBytes(length int) []byte {
	randomBytes := make([]byte, length)
	for i := range randomBytes {
		randomBytes[i] = byte(rand.Intn(math.MaxInt8))
	}
	return randomBytes
}
