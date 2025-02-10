package iptables

import (
	"context"
	"net"
	"net/netip"
	"os"
	"strconv"

	"github.com/docker/docker/libnetwork/iptables"

	"github.com/docker/docker/libnetwork/types"
)

func (n *network) AddPort(ctx context.Context, pb types.PortBinding, childHostIP netip.Addr) error {
	if err := n.setPerPortIptables(b, true); err != nil {
		return err
	}
	if err := n.filterPortMappedOnLoopback(b, true); err != nil {
		return err
	}
	if err := n.filterDirectAccess(b, true); err != nil {
		return err
	}
	return nil
}

func (n *bridgeNetwork) setPerPortIptables(b portBinding, enable bool) error {
	if (b.IP.To4() != nil) != (b.HostIP.To4() != nil) {
		// The binding is between containerV4 and hostV6 (not vice-versa as that
		// will have been rejected earlier). It's handled by docker-proxy, so no
		// additional iptables rules are required.
		return nil
	}
	v := iptables.IPv4
	if b.IP.To4() == nil {
		v = iptables.IPv6
	}

	if enabled, err := n.iptablesEnabled(v); err != nil || !enabled {
		// Nothing to do, iptables/ip6tables is not enabled.
		return nil
	}

	bridgeName := n.getNetworkBridgeName()
	proxyPath := n.userlandProxyPath()
	if err := setPerPortNAT(b, v, proxyPath, bridgeName, enable); err != nil {
		return err
	}

	if !n.gwMode(v).unprotected() {
		if err := setPerPortForwarding(b, v, bridgeName, enable); err != nil {
			return err
		}
	}
	return nil
}

func setPerPortNAT(b portBinding, ipv iptables.IPVersion, proxyPath string, bridgeName string, enable bool) error {
	if b.HostPort == 0 {
		// NAT is disabled.
		return nil
	}
	// iptables interprets "0.0.0.0" as "0.0.0.0/32", whereas we
	// want "0.0.0.0/0". "0/0" is correctly interpreted as "any
	// value" by both iptables and ip6tables.
	hostIP := "0/0"
	if !b.childHostIP.IsUnspecified() {
		hostIP = b.childHostIP.String()
	}
	args := []string{
		"-p", b.Proto.String(),
		"-d", hostIP,
		"--dport", strconv.Itoa(int(b.HostPort)),
		"-j", "DNAT",
		"--to-destination", net.JoinHostPort(b.IP.String(), strconv.Itoa(int(b.Port))),
	}
	hairpinMode := proxyPath == ""
	if !hairpinMode {
		args = append(args, "!", "-i", bridgeName)
	}
	if ipv == iptables.IPv6 {
		args = append(args, "!", "-s", "fe80::/10")
	}
	rule := iptables.Rule{IPVer: ipv, Table: iptables.Nat, Chain: DockerChain, Args: args}
	if err := appendOrDelChainRule(rule, "DNAT", enable); err != nil {
		return err
	}

	rule = iptables.Rule{IPVer: ipv, Table: iptables.Nat, Chain: "POSTROUTING", Args: []string{
		"-p", b.Proto.String(),
		"-s", b.IP.String(),
		"-d", b.IP.String(),
		"--dport", strconv.Itoa(int(b.Port)),
		"-j", "MASQUERADE",
	}}
	if err := appendOrDelChainRule(rule, "MASQUERADE", hairpinMode && enable); err != nil {
		return err
	}

	return nil
}

func setPerPortForwarding(b portBinding, ipv iptables.IPVersion, bridgeName string, enable bool) error {
	// Insert rules for open ports at the top of the filter table's DOCKER
	// chain (a per-network DROP rule, which must come after these per-port
	// per-container ACCEPT rules, is appended to the chain when the network
	// is created).
	rule := iptables.Rule{IPVer: ipv, Table: iptables.Filter, Chain: DockerChain, Args: []string{
		"!", "-i", bridgeName,
		"-o", bridgeName,
		"-p", b.Proto.String(),
		"-d", b.IP.String(),
		"--dport", strconv.Itoa(int(b.Port)),
		"-j", "ACCEPT",
	}}
	if err := programChainRule(rule, "OPEN PORT", enable); err != nil {
		return err
	}

	if b.Proto == types.SCTP && os.Getenv("DOCKER_IPTABLES_SCTP_CHECKSUM") == "1" {
		// Linux kernel v4.9 and below enables NETIF_F_SCTP_CRC for veth by
		// the following commit.
		// This introduces a problem when combined with a physical NIC without
		// NETIF_F_SCTP_CRC. As for a workaround, here we add an iptables entry
		// to fill the checksum.
		//
		// https://github.com/torvalds/linux/commit/c80fafbbb59ef9924962f83aac85531039395b18
		rule := iptables.Rule{IPVer: ipv, Table: iptables.Mangle, Chain: "POSTROUTING", Args: []string{
			"-p", b.Proto.String(),
			"--sport", strconv.Itoa(int(b.Port)),
			"-j", "CHECKSUM",
			"--checksum-fill",
		}}
		if err := appendOrDelChainRule(rule, "SCTP CHECKSUM", enable); err != nil {
			return err
		}
	}

	return nil
}

// filterPortMappedOnLoopback adds an iptables rule that drops remote
// connections to ports mapped on loopback addresses.
//
// This is a no-ip if the portBinding is for IPv6 (IPv6 loopback address is
// non-routable), or over a network with gw_mode=routed (PBs in routed mode
// don't map ports on the host).
func (n *bridgeNetwork) filterPortMappedOnLoopback(b portBinding, enable bool) error {
	hostIP := b.childHostIP
	if b.HostPort == 0 || !hostIP.IsLoopback() || b.childHostIP.To4() == nil {
		return nil
	}

	acceptMirrored := iptables.Rule{IPVer: iptables.IPv4, Table: iptables.Raw, Chain: "PREROUTING", Args: []string{
		"-p", b.Proto.String(),
		"-d", hostIP.String(),
		"--dport", strconv.Itoa(int(b.HostPort)),
		"-i", "loopback0",
		"-j", "ACCEPT",
	}}
	enableMirrored := enable && isRunningUnderWSL2MirroredMode()
	if err := appendOrDelChainRule(acceptMirrored, "LOOPBACK FILTERING - ACCEPT MIRRORED", enableMirrored); err != nil {
		return err
	}

	drop := iptables.Rule{IPVer: iptables.IPv4, Table: iptables.Raw, Chain: "PREROUTING", Args: []string{
		"-p", b.Proto.String(),
		"-d", hostIP.String(),
		"--dport", strconv.Itoa(int(b.HostPort)),
		"!", "-i", "lo",
		"-j", "DROP",
	}}
	if err := appendOrDelChainRule(drop, "LOOPBACK FILTERING - DROP", enable); err != nil {
		return err
	}

	return nil
}

// filterDirectAccess adds an iptables rule that drops 'direct' remote
// connections made to the container's IP address, when the network gateway
// mode is "nat".
//
// This is a no-op if the gw_mode is "nat-unprotected" or "routed".
func (n *bridgeNetwork) filterDirectAccess(b portBinding, enable bool) error {
	ipv := iptables.IPv4
	if b.IP.To4() == nil {
		ipv = iptables.IPv6
	}

	// gw_mode=nat-unprotected means there's minimal security for NATed ports,
	// so don't filter direct access.
	if n.gwMode(ipv).unprotected() || n.gwMode(ipv).routed() {
		return nil
	}

	bridgeName := n.getNetworkBridgeName()
	drop := iptables.Rule{IPVer: ipv, Table: iptables.Raw, Chain: "PREROUTING", Args: []string{
		"-p", b.Proto.String(),
		"-d", b.IP.String(), // Container IP address
		"--dport", strconv.Itoa(int(b.Port)), // Container port
		"!", "-i", bridgeName,
		"-j", "DROP",
	}}
	if err := appendOrDelChainRule(drop, "DIRECT ACCESS FILTERING - DROP", enable); err != nil {
		return err
	}

	return nil
}
