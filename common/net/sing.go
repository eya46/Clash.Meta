package net

import (
	"errors"
	"fmt"
	"io"
	"net"
	"runtime"
	"runtime/debug"

	"github.com/metacubex/mihomo/common/net/deadline"
	"github.com/metacubex/mihomo/log"

	"github.com/metacubex/sing/common"
	"github.com/metacubex/sing/common/bufio"
	"github.com/metacubex/sing/common/network"
)

var NewExtendedConn = bufio.NewExtendedConn
var NewExtendedWriter = bufio.NewExtendedWriter
var NewExtendedReader = bufio.NewExtendedReader

type ExtendedConn = network.ExtendedConn
type ExtendedWriter = network.ExtendedWriter
type ExtendedReader = network.ExtendedReader

var WriteBuffer = bufio.WriteBuffer

type ReadWaitOptions = network.ReadWaitOptions

var NewReadWaitOptions = network.NewReadWaitOptions
var CalculateFrontHeadroom = network.CalculateFrontHeadroom
var CalculateRearHeadroom = network.CalculateRearHeadroom

type ReaderWithUpstream = network.ReaderWithUpstream
type WithUpstreamReader = network.WithUpstreamReader
type WriterWithUpstream = network.WriterWithUpstream
type WithUpstreamWriter = network.WithUpstreamWriter
type WithUpstream = common.WithUpstream

var UnwrapReader = network.UnwrapReader
var UnwrapWriter = network.UnwrapWriter

func NewDeadlineConn(conn net.Conn) ExtendedConn {
	if deadline.IsPipe(conn) || deadline.IsPipe(UnwrapReader(conn)) {
		return NewExtendedConn(conn) // pipe always have correctly deadline implement
	}
	if deadline.IsConn(conn) || deadline.IsConn(UnwrapReader(conn)) {
		return NewExtendedConn(conn) // was a *deadline.Conn
	}
	return deadline.NewConn(conn)
}

func NeedHandshake(conn any) bool {
	if earlyConn, isEarlyConn := common.Cast[network.EarlyConn](conn); isEarlyConn && earlyConn.NeedHandshake() {
		return true
	}
	return false
}

type CountFunc = network.CountFunc

var Pipe = deadline.Pipe

func closeWrite(writer io.Closer) error {
	if c, ok := common.Cast[network.WriteCloser](writer); ok {
		return c.CloseWrite()
	}
	return writer.Close()
}

// Relay copies between left and right bidirectionally.
// like [bufio.CopyConn] but remove unneeded [context.Context] handle and the cost of [task.Group]
func Relay(leftConn, rightConn net.Conn) {
	defer func() {
		_ = leftConn.Close()
		_ = rightConn.Close()
	}()

	ch := make(chan error, 1)
	go func() {
		err := relayCopy(leftConn, rightConn, "left<-right")
		if err == nil {
			_ = closeWrite(leftConn)
		} else {
			_ = leftConn.Close()
		}
		ch <- err
	}()

	err := relayCopy(rightConn, leftConn, "right<-left")
	if err == nil {
		_ = closeWrite(rightConn)
	} else {
		_ = rightConn.Close()
	}
	<-ch
}

func relayCopy(dst, src net.Conn, direction string) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("relay panic (%s): %v", direction, r)
			log.Errorln("[RELAY] panic during copy %s: %v\n%s", direction, r, debug.Stack())
		}
	}()

	if runtime.GOOS == "windows" {
		return relayCopySafe(dst, src)
	}

	_, err = bufio.Copy(dst, src)
	return err
}

func relayCopySafe(dst, src net.Conn) error {
	buffer := make([]byte, 32*1024)
	for {
		n, readErr := src.Read(buffer)
		if n > 0 {
			written := 0
			for written < n {
				m, writeErr := dst.Write(buffer[written:n])
				if writeErr != nil {
					return writeErr
				}
				if m == 0 {
					return io.ErrShortWrite
				}
				written += m
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				return nil
			}
			return readErr
		}
	}
}
