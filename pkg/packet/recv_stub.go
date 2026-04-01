//go:build !linux && !darwin && !windows

package packet

import "fmt"

// Receiver placeholder type (non-supported OS).
type Receiver struct{}

func NewReceiver(ifaceName string, bpf string) (*Receiver, error) {
	_ = bpf
	return nil, fmt.Errorf("packet receiving is only supported on Linux, macOS and Windows")
}

func (r *Receiver) Recv() ([]byte, error) {
	return nil, fmt.Errorf("packet receiving is only supported on Linux, macOS and Windows")
}

func (r *Receiver) Close() error { return nil }
