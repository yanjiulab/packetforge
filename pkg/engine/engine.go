package engine

import (
	"errors"
	"fmt"
	"github.com/yanjiulab/packetforge/pkg/packet"
	"github.com/yanjiulab/packetforge/pkg/psl"
	"sync"
	"time"
)

var errExitAfterPacket = errors.New("exit after packet")

type ExpectFn func(expect *psl.Packet, opts *packet.BuildOptions, timeout time.Duration) error

// Run executes the PSL script: parsing and sending packets periodically/parallelly as requested
func Run(script *psl.Script, builder *packet.Builder, sendFn func([]byte) error, expectFn ExpectFn) error {
	for _, stmt := range script.Stmts {
		if err := runStmt(stmt, builder, sendFn, expectFn); err != nil {
			if errors.Is(err, errExitAfterPacket) {
				return nil
			}
			return err
		}
	}
	return nil
}

func runStmt(stmt psl.Stmt, builder *packet.Builder, sendFn func([]byte) error, expectFn ExpectFn) error {
	switch s := stmt.(type) {
	case *psl.PacketStmt:
		return runPacketStmt(s, builder, sendFn, expectFn)
	case *psl.BlockStmt:
		return runBlockStmt(s, builder, sendFn, expectFn)
	default:
		return fmt.Errorf("unknown stmt type")
	}
}

func runPacketStmt(s *psl.PacketStmt, builder *packet.Builder, sendFn func([]byte) error, expectFn ExpectFn) error {
	if s.Ignore {
		return nil
	}
	repeat := s.Repeat
	if repeat == 0 {
		repeat = 1
	}
	interval := time.Duration(s.Interval.Nanoseconds()) * time.Nanosecond
	for i := 0; i < repeat || repeat < 0; i++ {
		if repeat < 0 && i > 0 {
			time.Sleep(interval)
		} else if i > 0 && interval > 0 {
			time.Sleep(interval)
		}
		opts := &packet.BuildOptions{RepeatIndex: i}
		data, err := builder.Build(s.Packet, opts)
		if err != nil {
			return err
		}
		if err := sendFn(data); err != nil {
			return err
		}
		if s.Expect != nil {
			if expectFn == nil {
				return fmt.Errorf("@expect requires receive-enabled runtime")
			}
			timeout := time.Second
			if s.ExpectTimeout.Nanoseconds() > 0 {
				timeout = time.Duration(s.ExpectTimeout.Nanoseconds()) * time.Nanosecond
			}
			if err := expectFn(s.Expect, opts, timeout); err != nil {
				return err
			}
		}
		if repeat >= 0 && i == repeat-1 {
			break
		}
	}
	if s.Exit {
		return errExitAfterPacket
	}
	return nil
}

func runBlockStmt(s *psl.BlockStmt, builder *packet.Builder, sendFn func([]byte) error, expectFn ExpectFn) error {
	if s.Ignore {
		return nil
	}
	if s.Async {
		go func() {
			_ = runBlockSync(s, builder, sendFn, expectFn)
		}()
		return nil
	}
	return runBlockSync(s, builder, sendFn, expectFn)
}

func runBlockSync(s *psl.BlockStmt, builder *packet.Builder, sendFn func([]byte) error, expectFn ExpectFn) error {
	repeat := s.Repeat
	if repeat == 0 {
		repeat = 1
	}
	interval := time.Duration(s.Interval.Nanoseconds()) * time.Nanosecond
	for r := 0; r < repeat || repeat < 0; r++ {
		if r > 0 && interval > 0 {
			time.Sleep(interval)
		}
		for _, stmt := range s.Stmts {
			if err := runStmt(stmt, builder, sendFn, expectFn); err != nil {
				if errors.Is(err, errExitAfterPacket) {
					return err
				}
				return err
			}
		}
		if repeat >= 0 && r == repeat-1 {
			break
		}
	}
	return nil
}

// RunAsync starts asynchronous execution (like background heartbeat), the main logic uses wg to wait
func RunAsync(script *psl.Script, builder *packet.Builder, sendFn func([]byte) error, expectFn ExpectFn, wg *sync.WaitGroup) error {
	for _, stmt := range script.Stmts {
		if blk, ok := stmt.(*psl.BlockStmt); ok && blk.Async {
			wg.Add(1)
			go func(b *psl.BlockStmt) {
				defer wg.Done()
				_ = runBlockSync(b, builder, sendFn, expectFn)
			}(blk)
		} else {
			if err := runStmt(stmt, builder, sendFn, expectFn); err != nil {
				if errors.Is(err, errExitAfterPacket) {
					return nil
				}
				return err
			}
		}
	}
	return nil
}
