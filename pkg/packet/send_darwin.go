//go:build darwin

package packet

import (
	"fmt"
	"time"

	"github.com/google/gopacket/pcap"
)

// Sender sends raw ethernet frames via libpcap on macOS.
// Root privileges are typically required.
type Sender struct {
	ifaceName string
	handle    *pcap.Handle
}

// NewSender creates a packet sender for the specified interface on macOS.
func NewSender(ifaceName string) (*Sender, error) {
	// snaplen 65535, non-promiscuous, small timeout for write path.
	handle, err := pcap.OpenLive(ifaceName, 65535, false, 100*time.Millisecond)
	if err != nil {
		return nil, fmt.Errorf("open pcap on interface %s: %w", ifaceName, err)
	}
	return &Sender{
		ifaceName: ifaceName,
		handle:    handle,
	}, nil
}

// Send sends full ethernet frame bytes.
func (s *Sender) Send(data []byte) error {
	if s.handle == nil {
		return fmt.Errorf("pcap handle is closed")
	}
	if err := s.handle.WritePacketData(data); err != nil {
		return fmt.Errorf("send packet on %s: %w", s.ifaceName, err)
	}
	return nil
}

// Close closes sender resources.
func (s *Sender) Close() error {
	if s.handle != nil {
		s.handle.Close()
		s.handle = nil
	}
	return nil
}
