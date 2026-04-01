//go:build linux && !cgo

package packet

import "fmt"

func newReceiverWithBPF(ifaceName, bpf string) (*Receiver, error) {
	_ = ifaceName
	return nil, fmt.Errorf(
		"--recv-bpf on Linux requires a CGO build with libpcap (e.g. CGO_ENABLED=1 and libpcap-dev); rebuild or omit --recv-bpf",
	)
}
