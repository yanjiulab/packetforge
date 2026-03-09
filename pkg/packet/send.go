//go:build linux

package packet

import (
	"fmt"
	"net"
	"syscall"
)

const (
	afPacket    = 17
	sockRaw    = 3
	ethPAll    = 0x0003
	arpHrEther = 1
	packetHost = 0
)

// Sender sends raw ethernet frames via specified interface (requires root or CAP_NET_RAW, Linux only)
type Sender struct {
	iface *net.Interface
	fd    int
	addr  syscall.SockaddrLinklayer
}

// NewSender creates a packet sender, ifaceName is the interface name (e.g. eth0, lo)
func NewSender(ifaceName string) (*Sender, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("interface %s: %w", ifaceName, err)
	}
	fd, err := syscall.Socket(afPacket, sockRaw, int(htons(ethPAll)))
	if err != nil {
		return nil, fmt.Errorf("socket (requires root or CAP_NET_RAW): %w", err)
	}
	return &Sender{
		iface: iface,
		fd:    fd,
		addr: syscall.SockaddrLinklayer{
			Protocol: htons(ethPAll),
			Ifindex: iface.Index,
			Hatype:  uint16(arpHrEther),
			Pkttype: uint8(packetHost),
		},
	}, nil
}

func htons(v uint16) uint16 {
	return (v>>8)&0xff | (v&0xff)<<8
}

// Send sends raw packet (full ethernet frame)
func (s *Sender) Send(data []byte) error {
	return syscall.Sendto(s.fd, data, 0, &s.addr)
}

// Close closes the sending socket
func (s *Sender) Close() error {
	if s.fd >= 0 {
		err := syscall.Close(s.fd)
		s.fd = -1
		return err
	}
	return nil
}
