package l2disco

import (
	"context"
	"fmt"
	"net"
	"slices"

	"golang.org/x/sys/unix"
)

var naTemplate = []byte{
	0x88,       // Type (136=NA)
	0x00,       // Code (always 0)
	0x00, 0x00, // Checksum (filled in by the kernel)
	0x20,             // Flags, Router=0, Solicited=0, Override=1
	0x00, 0x00, 0x00, // Reserved
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Target IP
	0x02,                               // Option - target link layer address
	0x01,                               // Option length (32)
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Target MAC
}

type UnsolNA struct {
	pkt []byte
	sd  int
	sa  *unix.SockaddrInet6
	/*
		pc  *ipv6.PacketConn
		cm  *ipv6.ControlMessage
	*/
}

// NewUnsolNA returns a pointer to an object that can send unsolicited Neighbour
// Advertisements for ip and mac.
// https://datatracker.ietf.org/doc/html/rfc4861#section-4.4
func NewUnsolNA(ctx context.Context, ip net.IP, mac net.HardwareAddr, ifIndex int) (*UnsolNA, error) {
	sd, err := unix.Socket(unix.AF_INET6, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.IPPROTO_ICMPV6)
	if err != nil {
		return nil, err
	}
	// https://datatracker.ietf.org/doc/html/rfc4861#section-3.1
	//  By setting the Hop Limit to 255, Neighbor Discovery is immune to
	//  off-link senders that accidentally or intentionally send ND
	//  messages.
	if err := unix.SetsockoptInt(sd, unix.IPPROTO_IPV6, unix.IPV6_MULTICAST_HOPS, 255); err != nil {
		_ = unix.Close(sd)
		return nil, fmt.Errorf("set hop limit: %w", err)
	}

	saBind := &unix.SockaddrInet6{}
	copy(saBind.Addr[:], ip)
	if err := unix.Bind(sd, saBind); err != nil {
		_ = unix.Close(sd)
		return nil, fmt.Errorf("bind socket: %w", err)
	}

	pkt := slices.Clone(naTemplate)
	copy(pkt[8:24], ip)
	copy(pkt[26:32], mac)

	sa := &unix.SockaddrInet6{}
	copy(sa.Addr[:], net.IPv6linklocalallnodes)

	return &UnsolNA{
		pkt: pkt,
		sd:  sd,
		sa:  sa,
	}, nil
	/*
		// Open a socket ... it'll be bound to an address but the address doesn't matter,
		// no packets are to be received, and a source address is supplied when sending.
		netPC, err := net.ListenPacket("ip6:ipv6-icmp", "::1")
		if err != nil {
			return nil, err
		}
		pc := ipv6.NewPacketConn(netPC)

		// Block incoming packets.
		f := ipv6.ICMPFilter{}
		f.SetAll(true)
		if err := pc.SetICMPFilter(&f); err != nil {
			log.G(ctx).WithError(err).Errorf("failed to set ICMP filter")
		}

		cm := &ipv6.ControlMessage{
			// https://datatracker.ietf.org/doc/html/rfc4861#section-3.1
			//  By setting the Hop Limit to 255, Neighbor Discovery is immune to
			//  off-link senders that accidentally or intentionally send ND
			//  messages.
			HopLimit: 255,
			Src:      ip,
			IfIndex:  ifIndex,
		}

		pkt := slices.Clone(naTemplate)
		copy(pkt[8:24], ip)
		copy(pkt[26:32], mac)

		return &UnsolNA{
			pkt: pkt,
			pc:  pc,
			cm:  cm,
		}, nil
	*/
}

// Send sends an unsolicited ARP message.
func (un *UnsolNA) Send() error {
	return unix.Sendto(un.sd, un.pkt, 0, un.sa)
	/*
		n, err := un.pc.WriteTo(un.pkt, un.cm, &net.IPAddr{IP: net.IPv6linklocalallnodes})
		if err != nil {
			return err
		}
		if n != len(un.pkt) {
			return fmt.Errorf("failed to send packet: len:%d sent:%d", len(un.pkt), n)
		}
		return nil
	*/
}

// Close releases resources.
func (un *UnsolNA) Close() error {
	/*
		if un.pc != nil {
			err := un.pc.Close()
			un.pc = nil
	*/
	if un.sd >= 0 {
		err := unix.Close(un.sd)
		un.sd = -1
		return err
	}
	return nil
}
