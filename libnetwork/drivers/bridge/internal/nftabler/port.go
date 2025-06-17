// FIXME(thaJeztah): remove once we are a module; the go:build directive prevents go from downgrading language version to go1.16:
//go:build go1.22 && linux

package nftabler

import (
	"context"
	"fmt"
	"maps"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/containerd/log"
	"github.com/docker/docker/libnetwork/drivers/bridge/internal/firewaller"
	"github.com/docker/docker/libnetwork/internal/nftables"
	"github.com/docker/docker/libnetwork/types"
)

type pbContext struct {
	table nftables.TableRef
	conf  firewaller.NetworkConfigFam
	ipv   firewaller.IPVersion
}

type portRulers struct {
	forwarding       *portRuler
	hairpinMasq      *portRuler
	mappedOnLoopback *portRuler
}

func newPortRulers() *portRulers {
	return &portRulers{
		forwarding:       newPortRuler(),
		hairpinMasq:      newPortRuler(),
		mappedOnLoopback: newPortRuler(),
	}
}

type ipProto struct {
	ip    string
	proto types.Protocol
}

func (n *network) AddPorts(ctx context.Context, pbs []types.PortBinding) error {
	return n.modPorts(ctx, pbs, true)
}

func (n *network) DelPorts(ctx context.Context, pbs []types.PortBinding) error {
	return n.modPorts(ctx, pbs, false)
}

func (n *network) modPorts(ctx context.Context, pbs []types.PortBinding, enable bool) error {
	if n.config.Internal {
		return nil
	}

	ctx = log.WithLogger(ctx, log.G(ctx).WithFields(log.Fields{"bridge": n.config.IfName}))

	if enable && n.fw.cleaner != nil {
		n.fw.cleaner.DelPorts(ctx, n.config, pbs)
	}

	pbs4, pbs6 := splitByContainerFam(pbs)
	if n.fw.config.IPv4 {
		pbc := pbContext{table: n.fw.table4, conf: n.config.Config4, ipv: firewaller.IPv4}
		if err := n.setPerPortRules(ctx, pbs4, pbc, n.fw.config.WSL2Mirrored, enable); err != nil {
			return err
		}
	}
	if n.fw.config.IPv6 {
		pbc := pbContext{table: n.fw.table6, conf: n.config.Config6, ipv: firewaller.IPv6}
		if err := n.setPerPortRules(ctx, pbs6, pbc, n.fw.config.WSL2Mirrored, enable); err != nil {
			return err
		}
	}
	return nil
}

func splitByContainerFam(pbs []types.PortBinding) ([]types.PortBinding, []types.PortBinding) {
	var pbs4, pbs6 []types.PortBinding
	for _, pb := range pbs {
		if pb.IP.To4() != nil {
			pbs4 = append(pbs4, pb)
		} else {
			pbs6 = append(pbs6, pb)
		}
	}
	return pbs4, pbs6
}

func (n *network) setPerPortRules(ctx context.Context, pbs []types.PortBinding, pbc pbContext, wsl2Mirrored, enable bool) error {
	if err := n.setPerPortForwarding(pbs, pbc, enable); err != nil {
		return err
	}
	if err := n.setPerPortDNAT(pbs, pbc, enable); err != nil {
		return err
	}
	if err := n.setPerPortHairpinMasq(pbs, pbc, enable); err != nil {
		return err
	}
	if err := n.filterPortMappedOnLoopback(pbs, pbc, wsl2Mirrored, enable); err != nil {
		return err
	}
	if err := nftApply(ctx, pbc.table); err != nil {
		return fmt.Errorf("adding rules for bridge %s: %w", n.config.IfName, err)
	}
	return nil
}

func (n *network) setPerPortForwarding(pbs []types.PortBinding, pbc pbContext, enable bool) error {
	// It's possible to map multiple host ports to the same container port, and the
	// nftables package doesn't allow insertion of multiple rules - so, collect a list
	// of ports with the same ip/proto.
	for _, pb := range pbs {
		if pbc.conf.Unprotected {
			continue
		}
		// If the binding is between containerV4 and hostV6, could ignore the pb here
		// because it probably duplicates a 4-to-4 binding. But, it'll be de-duplicated
		// anyway, and it seems best not to make an assumption about how the bridge
		// driver has set up the bindings.
		n.ports.forwarding.update(ipProto{ip: pb.IP.String(), proto: pb.Proto}, pb.Port, enable)
	}
	return n.ports.forwarding.apply(pbc.table, chainFilterFwdIn(n.config.IfName), func(key ipProto, portRange string) (nftables.RuleGroup, []string) {
		rule := fmt.Sprintf("%s daddr %s %s dport %s counter accept",
			pbc.table.Family(), key.ip, key.proto, portRange)
		return fwdInPortsRuleGroup, []string{rule}
	})
}

// FIXME(robmry) - deduplicate
func (n *network) setPerPortDNAT(pbs []types.PortBinding, pbc pbContext, enable bool) error {
	type ruleKey struct {
		hip, cip netip.Addr
		proto    types.Protocol
	}
	rules := map[ruleKey][]portPair{}
	for _, pb := range pbs {
		// Nothing to do if NAT is disabled.
		if pb.HostPort == 0 {
			continue
		}
		// If the binding is between containerV4 and hostV6, NAT isn't possible (the mapping
		// is handled by docker-proxy).
		if (pb.IP.To4() != nil) != (pb.HostIP.To4() != nil) {
			continue
		}

		key := ruleKey{proto: pb.Proto}
		key.hip, _ = netip.AddrFromSlice(pb.HostIP)
		key.cip, _ = netip.AddrFromSlice(pb.IP)
		rules[key] = append(rules[key], portPair{a: pb.HostPort, b: pb.Port})
	}

	updater := pbc.table.ChainUpdateFunc(natChain, enable)
	for key, ports := range rules {
		slices.SortFunc(ports, func(a, b portPair) int {
			if a.b == b.b {
				return int(a.a - b.a)
			}
			return int(a.b - b.b)
		})
		var proxySkip string
		if !n.fw.config.Hairpin {
			proxySkip = fmt.Sprintf("iifname != %s ", n.config.IfName)
		}
		var v6LLSkip string
		if pbc.table.Family() == nftables.IPv6 {
			v6LLSkip = "ip6 saddr != fe80::/10 "
		}
		var daddrMatch string
		if !key.hip.Unmap().IsUnspecified() {
			daddrMatch = fmt.Sprintf("%s daddr %s ", pbc.table.Family(), key.hip.String())
		}
		intervals := sortedPortPairsToIntervals(ports)
		for _, interval := range intervals {
			if err := updater(initialRuleGroup, "%s%s%s%s dport %s counter dnat to %s comment DNAT",
				proxySkip, v6LLSkip, daddrMatch, key.proto, interval.a, net.JoinHostPort(key.cip.String(), interval.b)); err != nil {
				return fmt.Errorf("adding DNAT for %s %s:%s -> %s:%s/%s on %s: %w",
					pbc.table.Family(), key.hip.String(), interval.a, key.cip, interval.b, key.proto, n.config.IfName, err)
			}
		}
	}
	return nil
}

// setPerPortHairpinMasq allows containers to access their own published ports on the host
// when hairpin is enabled (no docker-proxy), by masquerading.
func (n *network) setPerPortHairpinMasq(pbs []types.PortBinding, pbc pbContext, enable bool) error {
	if !n.fw.config.Hairpin {
		return nil
	}
	for _, pb := range pbs {
		// Nothing to do if NAT is disabled.
		if pb.HostPort == 0 {
			continue
		}
		// If the binding is between containerV4 and hostV6, NAT isn't possible (it's
		// handled by docker-proxy).
		if (pb.IP.To4() != nil) != (pb.HostIP.To4() != nil) {
			continue
		}
		n.ports.hairpinMasq.update(ipProto{ip: pb.IP.String(), proto: pb.Proto}, pb.Port, enable)
	}
	return n.ports.hairpinMasq.apply(pbc.table, chainNatPostRtIn(n.config.IfName),
		func(key ipProto, portRange string) (nftables.RuleGroup, []string) {
			rule := fmt.Sprintf(`%s saddr %s %s daddr %s %s dport %s counter masquerade comment "MASQ TO OWN PORT"`,
				pbc.table.Family(), key.ip, pbc.table.Family(), key.ip, key.proto, portRange)
			return initialRuleGroup, []string{rule}
		})
}

// filterPortMappedOnLoopback adds a rule that drops remote connections to ports
// mapped to loopback addresses.
//
// This is a no-op if the portBinding is for IPv6 (IPv6 loopback address is
// non-routable), or over a network with gw_mode=routed (PBs in routed mode
// don't map ports on the host).
func (n *network) filterPortMappedOnLoopback(pbs []types.PortBinding, pbc pbContext, wsl2Mirrored, enable bool) error {
	if pbc.ipv == firewaller.IPv6 {
		return nil
	}
	for _, pb := range pbs {
		// Nothing to do if not binding to the loopback address.
		if pb.HostPort == 0 || !pb.HostIP.IsLoopback() {
			continue
		}
		// Mappings from host IPv6 to container IPv4 are handled by docker-proxy.
		if pb.HostIP.To4() == nil {
			continue
		}
		n.ports.mappedOnLoopback.update(ipProto{ip: pb.HostIP.String(), proto: pb.Proto}, pb.HostPort, enable)
	}
	return n.ports.mappedOnLoopback.apply(pbc.table, rawPreroutingChain,
		func(key ipProto, portRange string) (_ nftables.RuleGroup, rules []string) {
			if wsl2Mirrored {
				rule := fmt.Sprintf(`iifname loopback0 ip daddr %s %s dport %s counter accept comment "ACCEPT WSL2 LOOPBACK"`,
					key.ip, key.proto, portRange)
				rules = append(rules, rule)
			}
			rule := fmt.Sprintf(`iifname != lo ip daddr %s %s dport %s counter drop comment "DROP REMOTE LOOPBACK"`,
				key.ip, key.proto, portRange)
			rules = append(rules, rule)
			return rawPreroutingPortsRuleGroup, rules
		})
}

type portPair struct {
	a, b uint16
}

type intervalPair struct {
	a, b string
}

// sortedPortPairsToIntervals takes a sorted slice of portPair and returns a slice in
// which consecutive portPairs are deduplicated and combined into intervals if their
// "a" and "b" values are both incremented by one.
//
// For example given "[]portPair{ {8080, 80},{8081, 81},{8082, 82} }" the return value will be
// "[]intervalPair{ {"8080-8082", "80-82"} }".
//
// If an interval only contains a single value, it's returned as a single value. For
// example "[]portPair{ {8080, 80},{8080, 80} }" will return "[]intervalPair{ {"8080", "80"} }".
func sortedPortPairsToIntervals(ports []portPair) []intervalPair {
	if len(ports) == 0 {
		return nil
	}
	ports = append(ports, portPair{}) // Dummy entry, will not be included in the set.
	intervals := make([]intervalPair, 0, len(ports))
	rangeStart := ports[0]
	rangeEnd := ports[0]
	for _, lookahead := range ports[1:] {
		if lookahead == rangeEnd || (lookahead.a == rangeEnd.a+1 && lookahead.b == rangeEnd.b+1) {
			rangeEnd = lookahead
			continue
		}
		if rangeStart == rangeEnd {
			intervals = append(intervals, intervalPair{
				a: strconv.FormatUint(uint64(rangeEnd.a), 10),
				b: strconv.FormatUint(uint64(rangeEnd.b), 10),
			})
		} else {
			intervals = append(intervals, intervalPair{
				a: fmt.Sprintf("%d-%d", rangeStart.a, rangeEnd.a),
				b: fmt.Sprintf("%d-%d", rangeStart.b, rangeEnd.b),
			})
		}
		rangeStart = lookahead
		rangeEnd = lookahead
	}
	return intervals
}

// sortedPortSliceToSet takes a sorted slice of ports and returns a string containing
// an nftables-like set, where ports have been de-duplicated and consecutive ports are
// represented as ranges.
//
// If the input slice is not sorted, duplicates may be missed and the resulting
// set will not necessarily be combined into intervals (nftables will ignore
// duplicates, but it won't spot the intervals).
//
// For example, given ports "[]uint16{ 80, 80, 90, 91, 92 }" the return value will be
// "{ 80, 90-92 }".
//
// If there is only a single element in the set it's returned as a single element,
// so "[]uint16{ 80, 80 }" will return "80".
func sortedPortSliceToSet(ports []uint16) string {
	if len(ports) == 0 {
		return ""
	}
	ports = append(ports, 0) // Dummy entry, not be included in the set.
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

type portRuler struct {
	portSets map[ipProto]*portSet
}

func newPortRuler() *portRuler {
	return &portRuler{
		portSets: map[ipProto]*portSet{},
	}
}

func (pt *portRuler) update(key ipProto, port uint16, enable bool) {
	ps, ok := pt.portSets[key]
	if !ok {
		ps = newPortSet()
		pt.portSets[key] = ps
	}
	if enable {
		ps.insert(port)
	} else {
		ps.remove(port)
	}
}

// TODO(robmry) - make nftRanges idempotent, so that this can process one rule at a time.
func (pt *portRuler) apply(table nftables.TableRef, chainName string, rule func(key ipProto, portRange string) (nftables.RuleGroup, []string)) error {
	appendRule := table.ChainUpdateFunc(chainName, true)
	deleteRule := table.ChainUpdateFunc(chainName, false)
	for key, ports := range pt.portSets {
		oldRanges, newRanges := ports.nftRanges()
		if oldRanges == newRanges {
			continue
		}
		if oldRanges != "" {
			group, rulesToDelete := rule(key, oldRanges)
			for _, ruleToDelete := range rulesToDelete {
				if err := deleteRule(group, ruleToDelete); err != nil {
					return fmt.Errorf("deleting rule %s: %w", ruleToDelete, err)
				}
			}
		}
		if newRanges != "" {
			group, rulesToAppend := rule(key, newRanges)
			for _, ruleToAppend := range rulesToAppend {
				if err := appendRule(group, ruleToAppend); err != nil {
					return fmt.Errorf("adding rule %s: %w", ruleToAppend, err)
				}
			}
		}
	}
	return nil
}

type portSet struct {
	ports  map[uint16]int
	ranges string
}

func newPortSet() *portSet {
	return &portSet{
		ports: map[uint16]int{},
	}
}

func (ps *portSet) nftRanges() (string, string) {
	oldRanges := ps.ranges
	ps.ranges = sortedPortSliceToSet(slices.Sorted(maps.Keys(ps.ports)))
	return oldRanges, ps.ranges
}

func (ps *portSet) insert(port uint16) {
	ps.ports[port]++
}

func (ps *portSet) remove(port uint16) error {
	count := ps.ports[port]
	switch count {
	case 0:
		return fmt.Errorf("%d is not in port set, cannot remove it", port)
	case 1:
		delete(ps.ports, port)
	default:
		ps.ports[port] = count - 1
	}
	return nil
}
