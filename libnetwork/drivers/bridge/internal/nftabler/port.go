// FIXME(thaJeztah): remove once we are a module; the go:build directive prevents go from downgrading language version to go1.16:
//go:build go1.22 && linux

package nftabler

import (
	"context"
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"

	"github.com/containerd/log"
	"github.com/docker/docker/libnetwork/drivers/bridge/internal/firewaller"
	"github.com/docker/docker/libnetwork/internal/nftables"
	"github.com/docker/docker/libnetwork/types"
)

const acceptWSL2LoopbackComment = "ACCEPT WSL2 LOOPBACK"

type perPortFwdGrp struct {
	family firewaller.IPVersion
	ip     string
	proto  types.Protocol
}

type ppfMapT map[perPortFwdGrp][]uint16

func (n *network) AddPorts(ctx context.Context, pbs []types.PortBinding) error {
	return n.modPorts(ctx, pbs, true)
}

func (n *network) DelPorts(ctx context.Context, pbs []types.PortBinding) error {
	return n.modPorts(ctx, pbs, false)
}

func (n *network) modPorts(ctx context.Context, pbs []types.PortBinding, enable bool) error {
	ctx = log.WithLogger(ctx, log.G(ctx).WithFields(log.Fields{"bridge": n.IfName}))

	// TODO(robmry) - group these, use anon sets for ports
	ppfMap := ppfMapT{}
	for _, pb := range pbs {
		if err := n.setPerPortRules(ctx, pb, ppfMap, enable); err != nil {
			return err
		}
	}
	if err := n.setPerPortForwarding(ppfMap, enable); err != nil {
		return err
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

func (n *network) setPerPortRules(ctx context.Context, b types.PortBinding, ppfMap ppfMapT, enable bool) error {
	table := n.fw.table4
	conf := n.Config4
	fam := firewaller.IPv4
	famEnabled := n.fw.IPv4
	if b.IP.To4() == nil {
		table = n.fw.table6
		conf = n.Config6
		fam = firewaller.IPv6
		famEnabled = n.fw.IPv6
	}

	if !famEnabled || n.Internal {
		// Nothing to do.
		return nil
	}

	if err := filterPortMappedOnLoopback(ctx, table, b, enable); err != nil {
		return err
	}

	// If the binding is between containerV4 and hostV6, it's handled by docker-proxy, so no
	// additional rules are required.
	if (b.IP.To4() != nil) != (b.HostIP.To4() != nil) {
		return nil
	}

	if err := n.setPerPortNAT(table, b, enable); err != nil {
		return err
	}

	if !conf.Unprotected {
		// It's possible to map multiple host ports to the same container port, and the
		// nftables package doesn't allow insertion of multiple rules - so, collect all
		// the published port ranges and create a single rule for each published port or
		// port-range later.
		key := perPortFwdGrp{family: fam, ip: b.IP.String(), proto: b.Proto}
		ppfMap[key] = append(ppfMap[key], b.Port)
	}
	return nil
}

func (n *network) setPerPortForwarding(ppfMap ppfMapT, enable bool) error {
	for ppf, ports := range ppfMap {
		table := n.fw.getTable(ppf.family)
		updateFwdIn := table.ChainUpdateFunc(chainFilterFwdIn(n.IfName), enable)
		slices.Sort(ports)
		setVal := sortedPortSliceToSet(ports)
		if err := updateFwdIn(fwdInPortsRuleGroup, "%s daddr %s %s dport %s counter accept",
			table.Family(), ppf.ip, ppf.proto, setVal); err != nil {
			return fmt.Errorf("opening port %s %s:%s/%s on %s: %w", table.Family(), ppf.ip, setVal, ppf.proto, n.IfName, err)
		}
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
			return fmt.Errorf("adding MASQ TO OWN PORT for %s:%d -> %s:%d/%s: %w",
				b.HostIP.String(), b.HostPort, b.IP, b.Port, b.Proto, err)
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
func filterPortMappedOnLoopback(ctx context.Context, table nftables.TableRef, b types.PortBinding, enable bool) error {
	if b.HostPort == 0 || !b.HostIP.IsLoopback() || b.HostIP.To4() == nil {
		return nil
	}

	if firewaller.IsRunningUnderWSL2MirroredMode(ctx) {
		updater := table.ChainUpdateFunc(rawPreroutingChain, enable)
		if err := updater(rawPreroutingPortsRuleGroup,
			`iifname loopback0 ip daddr %s %s dport %d counter accept comment "%s"`,
			b.HostIP, b.Proto, b.HostPort, acceptWSL2LoopbackComment); err != nil {
			return fmt.Errorf("adding WSL2 loopback rule for %s: %w", b, err)
		}
	}

	updater := table.ChainUpdateFunc(rawPreroutingChain, enable)
	if err := updater(rawPreroutingPortsRuleGroup,
		`iifname != lo ip daddr %s %s dport %d counter drop comment "DROP REMOTE LOOPBACK"`,
		b.HostIP, b.Proto, b.HostPort); err != nil {
		return fmt.Errorf("adding loopback filter rule for %s: %w", b, err)
	}

	return nil
}

// sortedPortSliceToSet takes a sorted slice of ports and returns a string containing
// nftables-like set, where ports have been de-duplicated and consecutive ports are
// represented as ranges.
//
// If the input slice is not sorted, not duplicates may be missed and the resulting
// set will not necessarily be combined into intervals (nftables will ignore duplicates,
// but it won't spot the intervals).
//
// For example given ports "[]uint16{ 80, 80, 90, 91, 92 }" the return value will be
// "{ 80, 90-92 }".
//
// If there is only a single element in the set it's returned as a single element,
// so "[]uint16{ 80, 80 }" will return "80".
func sortedPortSliceToSet(ports []uint16) string {
	if len(ports) == 0 {
		return ""
	}
	ports = append(ports, 0) // Dummy entry, will not be included in the set.
	entries := make([]string, 0, len(ports))
	rangeStart := ports[0]
	rangeEnd := ports[0]
	for _, lookahead := range ports[1:] {
		if lookahead == rangeEnd || lookahead == rangeEnd+1 {
			rangeEnd = lookahead
			continue
		}
		if rangeStart == rangeEnd {
			entries = append(entries, strconv.FormatUint(uint64(rangeEnd), 10))
		} else {
			entries = append(entries, fmt.Sprintf("%d-%d", rangeStart, rangeEnd))
		}
		rangeStart = lookahead
		rangeEnd = lookahead
	}
	if len(entries) == 1 {
		return entries[0]
	}
	return "{ " + strings.Join(entries, ", ") + " }"
}
