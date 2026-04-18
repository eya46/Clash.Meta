package sing_tun

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metacubex/gvisor/pkg/tcpip/header"
	TS "github.com/metacubex/mihomo/component/tailscale"
	"github.com/metacubex/mihomo/log"
	tun "github.com/metacubex/sing-tun"
	"github.com/metacubex/sing/common/buf"
)

var errUnsupportedICMPEchoPacket = errors.New("unsupported ICMP echo packet")

type tailscalePingDestination struct {
	ctx          context.Context
	cancel       context.CancelFunc
	destination  netip.Addr
	routeContext tun.DirectRouteContext
	timeout      time.Duration
	closed       atomic.Bool
	inFlight     sync.WaitGroup
}

func newTailscalePingDestination(
	destination netip.Addr,
	routeContext tun.DirectRouteContext,
	timeout time.Duration,
) tun.DirectRouteDestination {
	ctx, cancel := context.WithCancel(context.Background())
	return &tailscalePingDestination{
		ctx:          ctx,
		cancel:       cancel,
		destination:  destination,
		routeContext: routeContext,
		timeout:      timeout,
	}
}

func (d *tailscalePingDestination) WritePacket(packet *buf.Buffer) error {
	if packet == nil {
		return nil
	}
	if d.IsClosed() {
		packet.Release()
		return context.Canceled
	}

	d.inFlight.Add(1)
	go d.reply(packet)
	return nil
}

func (d *tailscalePingDestination) reply(packet *buf.Buffer) {
	defer d.inFlight.Done()
	defer packet.Release()

	if d.IsClosed() {
		return
	}

	ctx, cancel := context.WithTimeout(d.ctx, d.timeout)
	defer cancel()

	result, err := TS.Ping(ctx, d.destination)
	if err != nil {
		if !d.IsClosed() && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
			log.Debugln("[ICMP] tailscale ping %s failed: %s", d.destination, err.Error())
		}
		return
	}

	if err := rewriteICMPEchoReply(packet); err != nil {
		if !d.IsClosed() {
			log.Debugln("[ICMP] rewrite tailscale echo reply for %s failed: %s", d.destination, err.Error())
		}
		return
	}

	if d.IsClosed() {
		return
	}

	if err := d.routeContext.WritePacket(packet.Bytes()); err != nil {
		if !d.IsClosed() {
			log.Debugln("[ICMP] write tailscale echo reply for %s failed: %s", d.destination, err.Error())
		}
		return
	}

	if result != nil {
		log.Debugln(
			"[ICMP] tailscale ping %s success latency=%.3fs node=%s",
			d.destination,
			result.LatencySeconds,
			result.NodeName,
		)
	}
}

func (d *tailscalePingDestination) Close() error {
	if !d.closed.CompareAndSwap(false, true) {
		return nil
	}
	d.cancel()
	d.inFlight.Wait()
	return nil
}

func (d *tailscalePingDestination) IsClosed() bool {
	return d.closed.Load()
}

func rewriteICMPEchoReply(packet *buf.Buffer) error {
	if packet == nil {
		return errors.New("packet is nil")
	}

	rawPacket := packet.Bytes()
	switch header.IPVersion(rawPacket) {
	case header.IPv4Version:
		totalLen, err := rewriteICMPv4EchoReply(rawPacket)
		if err != nil {
			return err
		}
		packet.Truncate(totalLen)
		return nil
	case header.IPv6Version:
		totalLen, err := rewriteICMPv6EchoReply(rawPacket)
		if err != nil {
			return err
		}
		packet.Truncate(totalLen)
		return nil
	default:
		return errors.New("unsupported IP version")
	}
}

func rewriteICMPv4EchoReply(packet []byte) (int, error) {
	if len(packet) < header.IPv4MinimumSize {
		return 0, errors.New("invalid IPv4 packet")
	}

	ipHdr := header.IPv4(packet)
	headerLen := int(ipHdr.HeaderLength())
	if headerLen < header.IPv4MinimumSize || len(packet) < headerLen {
		return 0, errors.New("invalid IPv4 header length")
	}

	totalLen := int(ipHdr.TotalLength())
	if totalLen < headerLen+header.ICMPv4MinimumSize || len(packet) < totalLen {
		return 0, errors.New("invalid IPv4 total length")
	}
	if ipHdr.Protocol() != uint8(header.ICMPv4ProtocolNumber) {
		return 0, errUnsupportedICMPEchoPacket
	}

	icmpHdr := header.ICMPv4(packet[headerLen:totalLen])
	if icmpHdr.Type() != header.ICMPv4Echo || icmpHdr.Code() != 0 {
		return 0, errUnsupportedICMPEchoPacket
	}

	sourceAddress := ipHdr.SourceAddress()
	ipHdr.SetSourceAddress(ipHdr.DestinationAddress())
	ipHdr.SetDestinationAddress(sourceAddress)
	icmpHdr.SetType(header.ICMPv4EchoReply)
	icmpHdr.SetChecksum(header.ICMPv4Checksum(icmpHdr, 0))
	ipHdr.SetChecksum(0)
	ipHdr.SetChecksum(^ipHdr.CalculateChecksum())
	return totalLen, nil
}

func rewriteICMPv6EchoReply(packet []byte) (int, error) {
	if len(packet) < header.IPv6MinimumSize {
		return 0, errors.New("invalid IPv6 packet")
	}

	ipHdr := header.IPv6(packet)
	payloadLen := int(ipHdr.PayloadLength())
	totalLen := header.IPv6MinimumSize + payloadLen
	if payloadLen < header.ICMPv6MinimumSize || len(packet) < totalLen {
		return 0, errors.New("invalid IPv6 payload length")
	}
	if ipHdr.TransportProtocol() != header.ICMPv6ProtocolNumber {
		return 0, errUnsupportedICMPEchoPacket
	}

	icmpHdr := header.ICMPv6(packet[header.IPv6MinimumSize:totalLen])
	if icmpHdr.Type() != header.ICMPv6EchoRequest || icmpHdr.Code() != 0 {
		return 0, errUnsupportedICMPEchoPacket
	}

	sourceAddress := ipHdr.SourceAddress()
	ipHdr.SetSourceAddress(ipHdr.DestinationAddress())
	ipHdr.SetDestinationAddress(sourceAddress)
	icmpHdr.SetType(header.ICMPv6EchoReply)
	icmpHdr.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
		Header: icmpHdr,
		Src:    ipHdr.SourceAddress(),
		Dst:    ipHdr.DestinationAddress(),
	}))
	return totalLen, nil
}
