//go:build !linux && !darwin && !windows

package packet

import "fmt"

// Sender placeholder type (non-Linux only supports -dry-run)
type Sender struct{}

func NewSender(ifaceName string) (*Sender, error) {
	return nil, fmt.Errorf("packet sending is only supported on Linux, macOS and Windows, please use -dry-run to only build packets")
}

func (s *Sender) Send(data []byte) error {
	return fmt.Errorf("only supports sending on Linux, macOS and Windows")
}

func (s *Sender) Close() error { return nil }
