package nftabler

import (
	"context"
	"fmt"
	"net"
	"strconv"

	"github.com/containerd/log"
	"github.com/docker/docker/libnetwork/drivers/bridge/internal/firewaller"
	"github.com/docker/docker/libnetwork/internal/nftables"
	"github.com/docker/docker/libnetwork/types"
)

func (n *network) AddPorts(ctx context.Context, pbs []types.PortBinding) error {
	return n.modPorts(ctx, pbs, true)
}

func (n *network) DelPorts(ctx context.Context, pbs []types.PortBinding) error {
	return n.modPorts(ctx, pbs, false)
}

func (n *network) modPorts(ctx context.Context, pbs []types.PortBinding, enable bool) error {
	ctx = log.WithLogger(ctx, log.G(ctx).WithFields(log.Fields{"bridge": n.IfName}))

	// TODO(robmry) - group these, use anon sets for ports
	for _, pb := range pbs {
		if err := n.setPerPortIptables(pb, enable); err != nil {
			return err
		}
	}

	// TODO(robmry) - only apply updates for updated tables...
	if n.fw.IPv4 {
		if err := nftApply(ctx, n.fw.table4); err != nil {
			return fmt.Errorf("adding rules for bridge %s: %w", n.IfName, err)
		}
	}
	if n.fw.IPv6 {
		if err := nftApply(ctx, n.fw.table6); err != nil {
			return fmt.Errorf("adding rules for bridge %s: %w", n.IfName, err)
		}
	}
	return nil
}

func (n *network) setPerPortIptables(b types.PortBinding, enable bool) error {
	table := n.fw.table4
	conf := n.Config4
	famEnabled := n.fw.IPv4
	if b.IP.To4() == nil {
		table = n.fw.table6
		conf = n.Config6
		famEnabled = n.fw.IPv6
	}

	if !famEnabled || n.Internal {
		// Nothing to do.
		return nil
	}

	if err := filterPortMappedOnLoopback(table, b, enable); err != nil {
		return err
	}

	if err := n.filterDirectAccess(table, conf, b, enable); err != nil {
		return err
	}

	// If the binding is between containerV4 and hostV6, it's handled by docker-proxy, so no
	// additional iptables rules are required.
	if (b.IP.To4() != nil) != (b.HostIP.To4() != nil) {
		return nil
	}

	if err := n.setPerPortNAT(table, b, enable); err != nil {
		return err
	}

	if !conf.Unprotected {
		if err := n.setPerPortForwarding(table, b, enable); err != nil {
			return err
		}
	}
	return nil
}

func (n *network) setPerPortForwarding(table nftables.TableRef, b types.PortBinding, enable bool) error {
	updateFwdIn := table.ChainUpdateFunc(chainFilterFwdIn(n.IfName), enable)
	if err := updateFwdIn(fwdInPortsRuleGroup, "%s daddr %s %s dport %d counter accept",
		table.Family(), b.IP.String(), b.Proto, b.Port); err != nil {
		return fmt.Errorf("opening port %s %s:%d/%s on %s: %w", table.Family(), b.IP, b.Port, b.Proto, n.IfName, err)
	}
	return nil
}

func (n *network) setPerPortNAT(table nftables.TableRef, b types.PortBinding, enable bool) error {
	// Nothing to do if NAT is disabled.
	if b.HostPort == 0 {
		return nil
	}

	var daddrMatch string
	if !b.HostIP.IsUnspecified() {
		daddrMatch = fmt.Sprintf("%s daddr %s ", table.Family(), b.HostIP.String())
	}
	var proxySkip string
	if !n.fw.Hairpin {
		proxySkip = fmt.Sprintf("iifname != %s ", n.IfName)
	}
	var v6LLSkip string
	if table.Family() == nftables.IPv6 {
		v6LLSkip = "ip6 saddr != fe80::/10 "
	}

	updater := table.ChainUpdateFunc(natChain, enable)
	if err := updater(initialRuleGroup, "%s%s%s%s dport %d counter dnat to %s comment DNAT",
		proxySkip, v6LLSkip, daddrMatch, b.Proto, b.HostPort, net.JoinHostPort(b.IP.String(), strconv.Itoa(int(b.Port)))); err != nil {
		return fmt.Errorf("adding DNAT for %s %s:%d -> %s:%d/%s on %s: %w",
			table.Family(), b.HostIP.String(), b.HostPort, b.IP, b.Port, b.Proto, n.IfName, err)
	}

	if n.fw.Hairpin {
		// Allow containers to access their own published ports on the host, by masquerading.
		updater = table.ChainUpdateFunc(chainNatPostRtIn(n.IfName), enable)
		if err := updater(initialRuleGroup, `%s saddr %s %s daddr %s %s dport %d counter masquerade comment "MASQ TO OWN PORT"`,
			table.Family(), b.IP.String(), table.Family(), b.IP.String(), b.Proto, b.Port); err != nil {
		}
	}

	return nil
}

// filterPortMappedOnLoopback adds a rule that drops remote connections to ports
// mapped to loopback addresses.
//
// This is a no-op if the portBinding is for IPv6 (IPv6 loopback address is
// non-routable), or over a network with gw_mode=routed (PBs in routed mode
// don't map ports on the host).
func filterPortMappedOnLoopback(table nftables.TableRef, b types.PortBinding, enable bool) error {
	if b.HostPort == 0 || !b.HostIP.IsLoopback() || b.HostIP.To4() == nil {
		return nil
	}

	if firewaller.IsRunningUnderWSL2MirroredMode() {
		updater := table.ChainUpdateFunc(rawPreroutingChain, enable)
		if err := updater(rawPreroutingPortsRuleGroup,
			`iifname loopback0 ip daddr %s %s dport %d counter accept comment "ACCEPT WSL2 LOOPBACK"`,
			b.HostIP, b.Proto, b.HostPort); err != nil {
			return fmt.Errorf("adding WSL2 loopback rule for %s: %w", b, err)
		}
	}

	updater := table.ChainUpdateFunc(rawPreroutingChain, enable)
	if err := updater(rawPreroutingPortsRuleGroup,
		`iifname != lo ip daddr %s %s dport %d counter drop comment "FILTER LOOPBACK"`,
		b.HostIP, b.Proto, b.HostPort); err != nil {
		return fmt.Errorf("adding loopback filter rule for %s: %w", b, err)
	}

	return nil
}

// filterDirectAccess adds a rule that drops 'direct' remote connections made to the
// container's IP address, when the network gateway mode is "nat".
//
// This is a no-op if the gw_mode is "nat-unprotected" or "routed", and if the mapping
// is from an IPv6 host address to an IPv4 container address.
func (n *network) filterDirectAccess(table nftables.TableRef, conf firewaller.NetworkConfigFam, b types.PortBinding, enable bool) error {
	if b.HostIP.To4() == nil && b.IP.To4() != nil {
		return nil
	}

	// gw_mode=nat-unprotected means there's minimal security for NATed ports,
	// so don't filter direct access.
	if conf.Unprotected || conf.Routed {
		return nil
	}

	updater := table.ChainUpdateFunc(rawPreroutingChain, enable)
	if err := updater(rawPreroutingPortsRuleGroup,
		`iifname != %s %s daddr %s %s dport %d counter drop comment "FILTER DIRECT ACCESS"`,
		n.IfName, table.Family(), b.IP, b.Proto, b.Port); err != nil {
		return fmt.Errorf("adding direct access filter rule for %s: %w", b, err)
	}

	return nil
}
