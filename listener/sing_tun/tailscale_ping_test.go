package sing_tun

import (
	"net/netip"
	"testing"

	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/header"
	"github.com/metacubex/sing/common/buf"
)

func TestRewriteICMPEchoReplyIPv4(t *testing.T) {
	src := netip.MustParseAddr("10.0.0.2")
	dst := netip.MustParseAddr("192.168.100.171")
	packet := buildICMPv4EchoRequest(src, dst, []byte("hello"))
	buffer := buf.As(packet).ToOwned()
	defer buffer.Release()

	if err := rewriteICMPEchoReply(buffer); err != nil {
		t.Fatalf("rewrite IPv4 echo reply: %v", err)
	}

	rawPacket := buffer.Bytes()
	ipHdr := header.IPv4(rawPacket)
	if got := netip.AddrFrom4(ipHdr.SourceAddress().As4()); got != dst {
		t.Fatalf("unexpected IPv4 source: got %s want %s", got, dst)
	}
	if got := netip.AddrFrom4(ipHdr.DestinationAddress().As4()); got != src {
		t.Fatalf("unexpected IPv4 destination: got %s want %s", got, src)
	}

	icmpHdr := header.ICMPv4(rawPacket[int(ipHdr.HeaderLength()):])
	if icmpHdr.Type() != header.ICMPv4EchoReply {
		t.Fatalf("unexpected ICMPv4 type: got %d want %d", icmpHdr.Type(), header.ICMPv4EchoReply)
	}
	if checksum := header.ICMPv4Checksum(icmpHdr, 0); checksum != icmpHdr.Checksum() {
		t.Fatalf("unexpected ICMPv4 checksum: got %d want %d", icmpHdr.Checksum(), checksum)
	}
}

func TestRewriteICMPEchoReplyIPv6(t *testing.T) {
	src := netip.MustParseAddr("fd7a:115c:a1e0::2")
	dst := netip.MustParseAddr("fd7a:115c:a1e0::100")
	packet := buildICMPv6EchoRequest(src, dst, []byte("hello"))
	buffer := buf.As(packet).ToOwned()
	defer buffer.Release()

	if err := rewriteICMPEchoReply(buffer); err != nil {
		t.Fatalf("rewrite IPv6 echo reply: %v", err)
	}

	rawPacket := buffer.Bytes()
	ipHdr := header.IPv6(rawPacket)
	if got := netip.AddrFrom16(ipHdr.SourceAddress().As16()); got != dst {
		t.Fatalf("unexpected IPv6 source: got %s want %s", got, dst)
	}
	if got := netip.AddrFrom16(ipHdr.DestinationAddress().As16()); got != src {
		t.Fatalf("unexpected IPv6 destination: got %s want %s", got, src)
	}

	icmpHdr := header.ICMPv6(rawPacket[header.IPv6MinimumSize:])
	if icmpHdr.Type() != header.ICMPv6EchoReply {
		t.Fatalf("unexpected ICMPv6 type: got %d want %d", icmpHdr.Type(), header.ICMPv6EchoReply)
	}
	if checksum := header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
		Header: icmpHdr,
		Src:    ipHdr.SourceAddress(),
		Dst:    ipHdr.DestinationAddress(),
	}); checksum != icmpHdr.Checksum() {
		t.Fatalf("unexpected ICMPv6 checksum: got %d want %d", icmpHdr.Checksum(), checksum)
	}
}

func buildICMPv4EchoRequest(src, dst netip.Addr, payload []byte) []byte {
	packet := make([]byte, header.IPv4MinimumSize+header.ICMPv4MinimumSize+len(payload))
	ipHdr := header.IPv4(packet)
	ipHdr.Encode(&header.IPv4Fields{
		TotalLength: uint16(len(packet)),
		TTL:         64,
		Protocol:    uint8(header.ICMPv4ProtocolNumber),
		SrcAddr:     tcpip.AddrFrom4(src.As4()),
		DstAddr:     tcpip.AddrFrom4(dst.As4()),
	})
	ipHdr.SetChecksum(^ipHdr.CalculateChecksum())

	icmpHdr := header.ICMPv4(packet[header.IPv4MinimumSize:])
	icmpHdr.SetType(header.ICMPv4Echo)
	icmpHdr.SetCode(0)
	copy(icmpHdr.Payload(), payload)
	icmpHdr.SetChecksum(header.ICMPv4Checksum(icmpHdr, 0))
	return packet
}

func buildICMPv6EchoRequest(src, dst netip.Addr, payload []byte) []byte {
	packet := make([]byte, header.IPv6MinimumSize+header.ICMPv6MinimumSize+len(payload))
	ipHdr := header.IPv6(packet)
	ipHdr.Encode(&header.IPv6Fields{
		PayloadLength:     uint16(header.ICMPv6MinimumSize + len(payload)),
		TransportProtocol: header.ICMPv6ProtocolNumber,
		HopLimit:          64,
		SrcAddr:           tcpip.AddrFrom16(src.As16()),
		DstAddr:           tcpip.AddrFrom16(dst.As16()),
	})

	icmpHdr := header.ICMPv6(packet[header.IPv6MinimumSize:])
	icmpHdr.SetType(header.ICMPv6EchoRequest)
	icmpHdr.SetCode(0)
	copy(icmpHdr.Payload(), payload)
	icmpHdr.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
		Header: icmpHdr,
		Src:    ipHdr.SourceAddress(),
		Dst:    ipHdr.DestinationAddress(),
	}))
	return packet
}
