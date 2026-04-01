//go:build windows

package packet

import (
	"fmt"
	"time"

	"github.com/google/gopacket/pcap"
)

// Receiver receives raw ethernet frames via libpcap-compatible backend on Windows.
type Receiver struct {
	ifaceName string
	handle    *pcap.Handle
}

// NewReceiver creates a packet receiver for the specified interface on Windows.
// bpf is a tcpdump-style filter expression (e.g. "icmp"); empty means no filter.
func NewReceiver(ifaceName string, bpf string) (*Receiver, error) {
	handle, err := pcap.OpenLive(ifaceName, 65535, true, 200*time.Millisecond)
	if err != nil {
		return nil, fmt.Errorf("open pcap on interface %s: %w", ifaceName, err)
	}
	if bpf != "" {
		if err := handle.SetBPFFilter(bpf); err != nil {
			handle.Close()
			return nil, fmt.Errorf("set BPF filter %q: %w", bpf, err)
		}
	}
	return &Receiver{
		ifaceName: ifaceName,
		handle:    handle,
	}, nil
}

// Recv receives one packet.
func (r *Receiver) Recv() ([]byte, error) {
	if r.handle == nil {
		return nil, fmt.Errorf("pcap handle is closed")
	}
	data, _, err := r.handle.ReadPacketData()
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), data...), nil
}

// Close closes receiver resources.
func (r *Receiver) Close() error {
	if r.handle != nil {
		r.handle.Close()
		r.handle = nil
	}
	return nil
}
