//go:build linux && cgo

package packet

import (
	"fmt"
	"time"

	"github.com/google/gopacket/pcap"
)

type pcapWrapper struct {
	h *pcap.Handle
}

func (w *pcapWrapper) readPacket() ([]byte, error) {
	data, _, err := w.h.ReadPacketData()
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), data...), nil
}

func (w *pcapWrapper) close() error {
	if w.h != nil {
		w.h.Close()
		w.h = nil
	}
	return nil
}

func newReceiverWithBPF(ifaceName, bpf string) (*Receiver, error) {
	handle, err := pcap.OpenLive(ifaceName, 65535, true, 200*time.Millisecond)
	if err != nil {
		return nil, fmt.Errorf("open pcap on interface %s (needed for --recv-bpf): %w", ifaceName, err)
	}
	if err := handle.SetBPFFilter(bpf); err != nil {
		handle.Close()
		return nil, fmt.Errorf("set BPF filter %q: %w", bpf, err)
	}
	return &Receiver{pcap: &pcapWrapper{h: handle}}, nil
}
