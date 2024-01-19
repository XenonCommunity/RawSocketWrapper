package RawSocket

import (
	"math"
	"math/rand"
	"time"
)

// validPort returns a valid port number.
// If the input port is less than or equal to 0, a random port number is generated.
// Otherwise, the input port is returned as is.
func validPort(port int) int {
	if port <= 0 {
		return rand.Intn(math.MaxInt8) + 1
	}
	return port
}

// randomTimestamp generates a random timestamp and returns it as a byte slice.
func randomTimestamp() []byte {
	// Get the current Unix time in nanoseconds.
	unixNano := time.Now().UnixNano()

	// Convert the Unix time to a uint32 value.
	val := uint32(unixNano)

	// Create a byte slice to store the timestamp data.
	timestampData := make([]byte, 8)

	// Split the uint32 value into four bytes and store them in the byte slice.
	for i := 0; i < 4; i++ {
		timestampData[i] = byte(val >> ((3 - i) * 8))
	}

	// Return the byte slice representing the random timestamp.
	return timestampData
}

// randomBytes generates a slice of random bytes with the specified length.
func randomBytes(length int) []byte {
	// Create a new slice with the given length
	bytes := make([]byte, length)

	// Iterate through each index of the slice
	for i := range bytes {
		// Generate a random byte value using rand.Intn
		// The maximum value is math.MaxInt8
		bytes[i] = byte(rand.Intn(math.MaxInt8))
	}

	// Return the generated slice of random bytes
	return bytes
}
