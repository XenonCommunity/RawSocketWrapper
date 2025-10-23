# Raw Socket Wrapper

Raw Socket Wrapper is a Go library designed to simplify the interface for creating and manipulating raw network packets. It supports various protocols and provides utilities for packet serialization and randomization.

### Key Features 🚀

- **Protocol Support**: Facilitates the creation and manipulation of TCP, UDP, and ICMP packets.
- **Packet Serialization**: Provides utilities to serialize packets for transmission.
- **Randomization Utilities**: Includes functions to generate random ports, timestamps, and byte slices for networking.

## Getting Started 🚦

## Installation

To use the IP Iterator, you can import the `RawSocket` package in your Go project:

```go
import "github.com/SyNdicateFoundation/RawSocketWrapper/RawSocket"
```

## Usage

The `IPIterator` struct represents an iterator over a collection of IP addresses. You can create a new instance of `IPIterator` using the `ToIPIterator` function:

```go
iterator := RawSocket.ToIPIterator("100.0.0.0/12", "192.168.1.1-192.168.1.10")
```

The `Next` method returns the next IP address in the iterator:

```go
for iterator.HasNext() {
    ip := iterator.Next()
    // Do something with the IP address
    fmt.Println(ip)
}
```

You can also shuffle the order of the IP addresses in the iterator using the `Shuffle` method:

```go
iterator.Shuffle()
```

### Prerequisites

- `github.com/google/gopacket`: A Go library for packet processing.
- `golang.org/x/sys`: Provides low-level operating system primitives.

### Library
The `IPIterator` struct has the following methods:

- `ToIPIterator(data ...string) *IPIterator`: Creates a new instance of `IPIterator` with the given data.
- `Next() net.IP`: Returns the next IP in the iterator.
- `Shuffle()`: Shuffles the order of the IP addresses in the iterator.
- `SetSkipLocal(b bool)`: Sets the `skipLocal` flag to the given value.
- `HasNext() bool`: Returns `true` if there is a next IP address in the iterator.

### Contribution Guidelines 🤝

Contributions are welcome! If you're interested in improving RawSocketWrapper, please feel free to make a pull request or open an issue.

