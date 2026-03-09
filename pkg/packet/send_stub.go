//go:build !linux

package packet

import "fmt"

// Sender placeholder type (non-Linux only supports -dry-run)
type Sender struct{}

func NewSender(ifaceName string) (*Sender, error) {
	return nil, fmt.Errorf("raw socket sending is only supported on Linux, please use -dry-run to only build packets")
}

func (s *Sender) Send(data []byte) error {
	return fmt.Errorf("only supports sending on Linux")
}

func (s *Sender) Close() error { return nil }
