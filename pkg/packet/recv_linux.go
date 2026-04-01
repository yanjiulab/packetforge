//go:build linux

package packet

import (
	"fmt"
	"net"
	"syscall"
)

// pcapLike is implemented only when CGO is enabled (see recv_linux_bpf_cgo.go).
type pcapLike interface {
	readPacket() ([]byte, error)
	close() error
}

// Receiver receives raw ethernet frames (Linux).
// Without a BPF filter it uses AF_PACKET; with a filter and CGO it uses libpcap (see recv_linux_bpf_cgo.go).
type Receiver struct {
	iface *net.Interface
	fd    int
	pcap  pcapLike
}

// NewReceiver creates a packet receiver on ifaceName.
// bpf is a tcpdump-style filter expression (e.g. "icmp", "tcp port 80"); empty means no filter.
// With a non-empty bpf, Linux requires CGO and libpcap (see recv_linux_bpf_cgo.go); without CGO use recv_linux_bpf_nocgo.go.
func NewReceiver(ifaceName string, bpf string) (*Receiver, error) {
	if bpf != "" {
		return newReceiverWithBPF(ifaceName, bpf)
	}
	return newReceiverRaw(ifaceName)
}

func newReceiverRaw(ifaceName string) (*Receiver, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("interface %s: %w", ifaceName, err)
	}
	fd, err := syscall.Socket(afPacket, sockRaw, int(htons(ethPAll)))
	if err != nil {
		return nil, fmt.Errorf("socket (requires root or CAP_NET_RAW): %w", err)
	}
	addr := &syscall.SockaddrLinklayer{
		Protocol: htons(ethPAll),
		Ifindex:  iface.Index,
	}
	if err := syscall.Bind(fd, addr); err != nil {
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("bind receiver on %s: %w", ifaceName, err)
	}
	return &Receiver{iface: iface, fd: fd}, nil
}

// Recv receives one full ethernet frame.
func (r *Receiver) Recv() ([]byte, error) {
	if r.pcap != nil {
		return r.pcap.readPacket()
	}
	buf := make([]byte, 65535)
	n, _, err := syscall.Recvfrom(r.fd, buf, 0)
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), buf[:n]...), nil
}

// Close closes the receiving socket.
func (r *Receiver) Close() error {
	if r.pcap != nil {
		err := r.pcap.close()
		r.pcap = nil
		return err
	}
	if r.fd >= 0 {
		err := syscall.Close(r.fd)
		r.fd = -1
		return err
	}
	return nil
}
