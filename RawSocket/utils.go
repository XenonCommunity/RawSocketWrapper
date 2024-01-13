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

// randomTimestamp returns a byte slice representing a random timestamp.
func randomTimestamp() []byte {
	// Generate a random timestamp value using the current Unix time in nanoseconds.
	val := uint32(time.Now().UnixNano())

	// Initialize a secret value.
	secr := uint32(0)

	// Create a byte slice with a length of 8 to store the timestamp data.
	timestampData := make([]byte, 8)

	// Extract and store the four bytes of the timestamp value in the byte slice.
	timestampData[0] = byte(val >> 24)
	timestampData[1] = byte(val >> 16)
	timestampData[2] = byte(val >> 8)
	timestampData[3] = byte(val)

	// Extract and store the four bytes of the secret value in the byte slice.
	timestampData[4] = byte(secr >> 24)
	timestampData[5] = byte(secr >> 16)
	timestampData[6] = byte(secr >> 8)
	timestampData[7] = byte(secr)

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
