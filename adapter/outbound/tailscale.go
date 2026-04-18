package outbound

import (
	"context"
	"net"
	"strconv"
	"time"

	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/component/loopback"
	TS "github.com/metacubex/mihomo/component/tailscale"
	C "github.com/metacubex/mihomo/constant"
)

type Tailscale struct {
	*Base
	loopBack *loopback.Detector
}

type connectedPacketConn struct {
	conn   net.Conn
	remote net.Addr
}

func tailscaleRemoteAddress(metadata *C.Metadata) string {
	if metadata != nil && metadata.DstIP.IsValid() {
		return net.JoinHostPort(
			metadata.DstIP.String(),
			strconv.FormatUint(uint64(metadata.DstPort), 10),
		)
	}
	return metadata.RemoteAddress()
}

func (c *connectedPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	n, err = c.conn.Read(p)
	return n, c.remote, err
}

func (c *connectedPacketConn) WriteTo(p []byte, _ net.Addr) (n int, err error) {
	return c.conn.Write(p)
}

func (c *connectedPacketConn) Close() error {
	return c.conn.Close()
}

func (c *connectedPacketConn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *connectedPacketConn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

func (c *connectedPacketConn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *connectedPacketConn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

func (t *Tailscale) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	if err := t.loopBack.CheckConn(metadata); err != nil {
		return nil, err
	}

	conn, err := TS.DialContext(ctx, "tcp", tailscaleRemoteAddress(metadata))
	if err != nil {
		return nil, err
	}
	return t.loopBack.NewConn(NewConn(conn, t)), nil
}

func (t *Tailscale) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (C.PacketConn, error) {
	if err := t.loopBack.CheckPacketConn(metadata); err != nil {
		return nil, err
	}

	conn, err := TS.DialContext(ctx, "udp", tailscaleRemoteAddress(metadata))
	if err != nil {
		return nil, err
	}

	packetConn := &connectedPacketConn{
		conn:   conn,
		remote: metadata.UDPAddr(),
	}

	return t.loopBack.NewPacketConn(
		newPacketConn(N.NewThreadSafePacketConn(packetConn), t),
	), nil
}

func (t *Tailscale) ResolveUDP(_ context.Context, _ *C.Metadata) error {
	return nil
}

func NewTailscale() *Tailscale {
	return &Tailscale{
		Base: &Base{
			name:   TS.ProxyName(),
			addr:   TS.ProxyName(),
			tp:     C.Tailscale,
			udp:    true,
			prefer: C.DualStack,
		},
		loopBack: loopback.NewDetector(),
	}
}
