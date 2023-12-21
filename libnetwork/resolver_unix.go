//go:build !windows

package libnetwork

import (
	"fmt"
	"net"

	"github.com/docker/docker/libnetwork/iptables"
)

const (
	// output chain used for docker embedded DNS resolver
	outputChain = "DOCKER_OUTPUT"
	// postrouting chain used for docker embedded DNS resolver
	postroutingChain = "DOCKER_POSTROUTING"
)

func (r *Resolver) listenZoneId(prefix string) string {
	if r.listenIPv6 {
		return prefix + "lo"
	}
	return ""
}

func (r *Resolver) setupIPTable() error {
	if r.err != nil {
		return r.err
	}
	resolverIP := r.listenAddress
	_, listenPortUDP, _ := net.SplitHostPort(r.conn.LocalAddr().String())
	_, listenPortTCP, _ := net.SplitHostPort(r.tcpListen.Addr().String())
	rules := [][]string{
		{"-t", "nat", "-I", outputChain, "-d", resolverIP, "-p", "udp", "--dport", dnsPort, "-j", "DNAT", "--to-destination", ":" + listenPortUDP},
		{"-t", "nat", "-I", postroutingChain, "-s", resolverIP, "-p", "udp", "--sport", listenPortUDP, "-j", "SNAT", "--to-source", ":" + dnsPort},
		{"-t", "nat", "-I", outputChain, "-d", resolverIP, "-p", "tcp", "--dport", dnsPort, "-j", "DNAT", "--to-destination", ":" + listenPortTCP},
		{"-t", "nat", "-I", postroutingChain, "-s", resolverIP, "-p", "tcp", "--sport", listenPortTCP, "-j", "SNAT", "--to-source", ":" + dnsPort},
	}

	var setupErr error
	err := r.backend.ExecFunc(func() {
		var iptable *iptables.IPTable
		if r.listenIPv6 {
			iptable = iptables.GetIptable(iptables.IPv6)
		} else {
			iptable = iptables.GetIptable(iptables.IPv4)
		}

		// insert outputChain and postroutingchain
		if iptable.ExistsNative("nat", "OUTPUT", "-d", resolverIP, "-j", outputChain) {
			if err := iptable.RawCombinedOutputNative("-t", "nat", "-F", outputChain); err != nil {
				setupErr = err
				return
			}
		} else {
			if err := iptable.RawCombinedOutputNative("-t", "nat", "-N", outputChain); err != nil {
				setupErr = err
				return
			}
			if err := iptable.RawCombinedOutputNative("-t", "nat", "-I", "OUTPUT", "-d", resolverIP, "-j", outputChain); err != nil {
				setupErr = err
				return
			}
		}

		if iptable.ExistsNative("nat", "POSTROUTING", "-d", resolverIP, "-j", postroutingChain) {
			if err := iptable.RawCombinedOutputNative("-t", "nat", "-F", postroutingChain); err != nil {
				setupErr = err
				return
			}
		} else {
			if err := iptable.RawCombinedOutputNative("-t", "nat", "-N", postroutingChain); err != nil {
				setupErr = err
				return
			}
			if err := iptable.RawCombinedOutputNative("-t", "nat", "-I", "POSTROUTING", "-d", resolverIP, "-j", postroutingChain); err != nil {
				setupErr = err
				return
			}
		}

		for _, rule := range rules {
			if err := iptable.RawCombinedOutputNative(rule...); err != nil {
				setupErr = fmt.Errorf("set up rule failed, %v, %w", rule, err)
				return
			}
		}
	})
	if err != nil {
		return err
	}
	return setupErr
}
