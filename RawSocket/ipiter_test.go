package RawSocket

import "testing"

func TestToIPIterator(t *testing.T) {
	t.Log("TestToIPIterator")

	// Test case 2: Single element data
	iterator := ToIPIterator("0.0.0.0/0")

	for iterator.HasNext() {
		iterator.Next()
		continue
	}
}
