package network

// Collect and decode broadcast ARP and unsolicited ICMP6 Neighbour Advertisement messages...

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"syscall"
	"testing"
	"time"

	"github.com/docker/docker/internal/nlwrap"
	"gotest.tools/v3/assert"
)

// ARPPkt represents an Ethernet ARP packet and a timestamp.
type ARPPkt struct {
	Timestamp time.Time
	Data      []byte
}

// UnpackEth checks the packet is a valid Ethernet ARP packet, and returns
// sender and target hardware and protocol addresses, and true, if it is.
func (ap ARPPkt) UnpackEth() (sh, th net.HardwareAddr, sp, tp netip.Addr, err error) {
	if len(ap.Data) != 28 {
		return sh, th, sp, tp, fmt.Errorf("packet size %d", len(ap.Data))
	}
	// Hardware type (1)
	if ap.Data[0] != 0 || ap.Data[1] != 1 {
		return sh, th, sp, tp, fmt.Errorf("hardware type %v", ap.Data[0:2])
	}
	// Protocol type (0x800).
	if ap.Data[2] != 8 || ap.Data[3] != 0 {
		return sh, th, sp, tp, fmt.Errorf("protocol type %v", ap.Data[2:4])
	}
	// Hardware length (6)
	if ap.Data[4] != 6 {
		return sh, th, sp, tp, fmt.Errorf("hardware length %v", ap.Data[4])
	}
	// Protocol length (4)
	if ap.Data[5] != 4 {
		return sh, th, sp, tp, fmt.Errorf("protocol length %v", ap.Data[5])
	}
	// Operation (1=request, 2=reply)
	if ap.Data[6] != 0 || ap.Data[7] != 1 {
		return sh, th, sp, tp, fmt.Errorf("operation %v", ap.Data[6:8])
	}

	// Sender hardware address
	sh = make(net.HardwareAddr, 6)
	copy(sh, ap.Data[8:14])
	// Sender protocol address
	sp, _ = netip.AddrFromSlice(ap.Data[14:18])

	// Target hardware address
	th = make(net.HardwareAddr, 6)
	copy(th, ap.Data[18:24])
	// Target protocol address
	tp, _ = netip.AddrFromSlice(ap.Data[24:28])

	return sh, th, sp, tp, nil
}

// CollectBcastARPs collects broadcast ARPs from interface ifname. It returns a stop
// function, to stop collection and return a slice of collected packets, with
// timestamps added when they were received in userspace.
func CollectBcastARPs(t *testing.T, ifname string) (stop func() []ARPPkt) {
	sd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_DGRAM, int(htons(syscall.ETH_P_ARP)))
	assert.NilError(t, err)
	assert.Assert(t, sd >= 0)

	link, err := nlwrap.LinkByName(ifname)
	assert.NilError(t, err)

	err = syscall.Bind(sd, &syscall.SockaddrLinklayer{
		Protocol: htons(syscall.ETH_P_ARP),
		Pkttype:  syscall.PACKET_BROADCAST,
		Ifindex:  link.Attrs().Index,
	})
	assert.NilError(t, err)

	err = syscall.SetsockoptTimeval(sd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &syscall.Timeval{Sec: 1})
	assert.NilError(t, err)

	stopC := make(chan struct{})
	stoppedC := make(chan struct{})
	var pkts []ARPPkt
	go func() {
		defer close(stoppedC)
		defer syscall.Close(sd)
		for {
			buf := make([]byte, 50)
			n, err := syscall.Read(sd, buf)
			if err != nil {
				if errors.Is(err, syscall.EINTR) {
					continue
				}
				if errors.Is(err, syscall.EWOULDBLOCK) {
					select {
					case <-stopC:
						return
					default:
						continue
					}
				}
				t.Log("ARP read error:", err, "sd", sd)
				return
			}
			pkts = append(pkts, ARPPkt{
				Timestamp: time.Now(),
				Data:      buf[:n],
			})
		}
	}()

	return func() []ARPPkt {
		select {
		case <-stopC:
		default:
			close(stopC)
		}
		<-stoppedC
		return pkts
	}
}

// From https://github.com/mdlayher/packet/blob/f9999b41d9cfb0586e75467db1c81cfde4f965ba/packet_linux.go#L238-L248
func htons(i uint16) uint16 {
	var bigEndian [2]byte
	binary.BigEndian.PutUint16(bigEndian[:], i)
	return binary.NativeEndian.Uint16(bigEndian[:])
}

type ICMP6Pkt struct {
	Timestamp time.Time
	From      net.Addr
	Data      []byte
}

func (pkt ICMP6Pkt) UnpackUnsolNA(t *testing.T) (th net.HardwareAddr, tp netip.Addr, err error) {
	// Treat the packet as invalid unless it's sized for a NA message
	// with a link address option.
	if len(pkt.Data) != 32 {
		return th, tp, fmt.Errorf("packet size %d", len(pkt.Data))
	}
	// Type (136=NA)
	if pkt.Data[0] != 136 {
		return th, tp, fmt.Errorf("type %d", pkt.Data[0])
	}
	// Code
	if pkt.Data[1] != 0 {
		return th, tp, fmt.Errorf("code %d", pkt.Data[1])
	}
	// TODO(robmry) checksum pkt.Data[2:4]
	// Router flag (not sent by a router)
	if pkt.Data[4]&0x80 != 0 {
		return th, tp, errors.New("flag Router is set")
	}
	// Solicited flag (unsolicited)
	if pkt.Data[4]&0x40 != 0 {
		return th, tp, errors.New("flag Solicited is set")
	}
	// Override flag (SHOULD be set in an unsolicited advertisement)
	if pkt.Data[4]&0x20 == 0 {
		return th, tp, errors.New("flag Override is not set")
	}
	// Reserved pkt.Data[4:8]
	// Target address
	tp, _ = netip.AddrFromSlice(pkt.Data[8:24])
	// Options (02=link address, 01=length 8)
	if pkt.Data[24] != 2 || pkt.Data[25] != 1 {
		return th, tp, fmt.Errorf("option %d length %d", pkt.Data[24], pkt.Data[25])
	}
	// Link address
	th = make(net.HardwareAddr, 6)
	copy(th, pkt.Data[26:32])

	return th, tp, nil
}

// CollectICMP6 collects ICMP6 packets received on the interface with address addr.
// It returns a stop function, to stop collection and return a slice of collected packets.
func CollectICMP6(t *testing.T, ifname string) (stop func() []ICMP6Pkt) {
	sd, err := syscall.Socket(syscall.AF_INET6, syscall.SOCK_RAW, syscall.IPPROTO_ICMPV6)
	assert.NilError(t, err)
	assert.Assert(t, sd >= 0)

	link, err := nlwrap.LinkByName(ifname)
	assert.NilError(t, err)

	mreq := &syscall.IPv6Mreq{
		Interface: uint32(link.Attrs().Index),
	}
	copy(mreq.Multiaddr[:], net.IPv6linklocalallnodes)
	err = syscall.SetsockoptIPv6Mreq(sd, syscall.IPPROTO_IPV6, syscall.IPV6_JOIN_GROUP, mreq)
	assert.NilError(t, err)

	err = syscall.SetsockoptTimeval(sd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &syscall.Timeval{Sec: 1})
	assert.NilError(t, err)

	stopC := make(chan struct{})
	stoppedC := make(chan struct{})
	var pkts []ICMP6Pkt
	go func() {
		defer close(stoppedC)
		defer syscall.Close(sd)
		for {
			buf := make([]byte, 50)
			n, err := syscall.Read(sd, buf)
			if err != nil {
				if errors.Is(err, syscall.EINTR) {
					continue
				}
				if errors.Is(err, syscall.EWOULDBLOCK) {
					select {
					case <-stopC:
						return
					default:
						continue
					}
				}
				t.Log("ARP read error:", err, "sd", sd)
				return
			}
			pkts = append(pkts, ICMP6Pkt{
				Timestamp: time.Now(),
				Data:      buf[:n],
			})
		}
	}()

	return func() []ICMP6Pkt {
		select {
		case <-stopC:
		default:
			close(stopC)
		}
		<-stoppedC
		return pkts
	}
}
