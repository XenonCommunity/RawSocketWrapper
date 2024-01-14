package RawSocket

import "testing"

func TestToIPIterator(t *testing.T) {
	// Test case 2: Single element data
	iterator := ToIPIterator("0.0.0.0/0")

	for iterator.HasNext() {
		iterator.Next()
		continue
	}
}
