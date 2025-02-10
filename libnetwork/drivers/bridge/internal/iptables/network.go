package iptables

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"

	"github.com/docker/docker/libnetwork/drivers/bridge/internal/pktfilter"

	"github.com/containerd/log"
	"github.com/docker/docker/errdefs"
	"github.com/docker/docker/internal/nlwrap"
	"github.com/docker/docker/libnetwork/iptables"
	"github.com/docker/docker/libnetwork/types"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
)

type network struct {
	pktfilter.NetworkConfig
	cleanFuncs iptablesCleanFuncs
	ipt        *IPTables
}

type (
	iptableCleanFunc   func() error
	iptablesCleanFuncs []iptableCleanFunc
)

func (ipt *IPTables) AddNetwork(nc pktfilter.NetworkConfig) (pktfilter.Network, error) {
	n := &network{
		NetworkConfig: nc,
		ipt:           ipt,
	}
	if ipt.config.IPv4 {
		if err := n.setupIPTables(iptables.IPv4, n.Config4, ipsetExtBridges4); err != nil {
			return nil, err
		}
	}
	if ipt.config.IPv6 {
		if err := n.setupIPTables(iptables.IPv6, n.Config6, ipsetExtBridges6); err != nil {
			return nil, err
		}
	}
	return n, nil
}

func (n *network) registerIptCleanFunc(clean iptableCleanFunc) {
	n.cleanFuncs = append(n.cleanFuncs, clean)
}

func (n *network) setupIPTables(ipVersion iptables.IPVersion, config pktfilter.NetworkConfigFam, ipsetName string) error {
	var err error

	if n.Internal {
		if err = setupInternalNetworkRules(n.IfName, config.Prefix, n.ICC, true); err != nil {
			return fmt.Errorf("Failed to Setup IP tables: %w", err)
		}
		n.registerIptCleanFunc(func() error {
			return setupInternalNetworkRules(n.IfName, config.Prefix, n.ICC, false)
		})
	} else {
		if err = setupNonInternalNetworkRules(ipVersion, config, n.ipt.config.Hairpin, true); err != nil {
			return fmt.Errorf("Failed to Setup IP tables: %w", err)
		}
		n.registerIptCleanFunc(func() error {
			return setupNonInternalNetworkRules(ipVersion, config, n.ipt.config.Hairpin, false)
		})

		if err := iptables.AddInterfaceFirewalld(config.BridgeName); err != nil {
			return err
		}
		n.registerIptCleanFunc(func() error {
			if err := iptables.DelInterfaceFirewalld(config.BridgeName); err != nil && !errdefs.IsNotFound(err) {
				return err
			}
			return nil
		})

		err = deleteLegacyFilterRules(ipVersion, config.BridgeName)
		if err != nil {
			return fmt.Errorf("failed to delete legacy rules in filter-FORWARD: %w", err)
		}

		if err := n.setDefaultForwardRule(ipVersion, config.BridgeName); err != nil {
			return err
		}

		cidr, _ := maskedAddr.Mask.Size()
		if cidr == 0 {
			return fmt.Errorf("no CIDR for bridge %s addr %s", config.BridgeName, maskedAddr)
		}
		ipsetEntry := &netlink.IPSetEntry{
			IP:   maskedAddr.IP,
			CIDR: uint8(cidr),
		}
		if err := netlink.IpsetAdd(ipsetName, ipsetEntry); err != nil {
			if !errors.Is(err, nl.IPSetError(nl.IPSET_ERR_EXIST)) {
				return fmt.Errorf("failed to add bridge %s (%s) to ipset: %w",
					config.BridgeName, maskedAddr, err)
			}
			log.G(context.TODO()).WithFields(log.Fields{
				"ipset":  ipsetName,
				"bridge": config.BridgeName,
				"subnet": maskedAddr,
			}).Warnf("Subnet was already in the ipset")
		}
		n.registerIptCleanFunc(func() error {
			return netlink.IpsetDel(ipsetName, ipsetEntry)
		})
	}
	return nil
}

func setICMP(ipv iptables.IPVersion, bridgeName string, enable bool) error {
	icmpProto := "icmp"
	if ipv == iptables.IPv6 {
		icmpProto = "icmpv6"
	}
	icmpRule := iptables.Rule{IPVer: ipv, Table: iptables.Filter, Chain: DockerChain, Args: []string{
		"-o", bridgeName,
		"-p", icmpProto,
		"-j", "ACCEPT",
	}}
	return appendOrDelChainRule(icmpRule, "ICMP", enable)
}

// deleteLegacyFilterRules removes the legacy per-bridge rules from the filter-FORWARD
// chain. This is required for users upgrading the Engine to v28.0.
// TODO(aker): drop this function once Mirantis latest LTS is v28.0 (or higher).
func deleteLegacyFilterRules(ipVer iptables.IPVersion, bridgeName string) error {
	iptable := iptables.GetIptable(ipVer)
	// Delete legacy per-bridge jump to the DOCKER chain from the FORWARD chain, if it exists.
	// These rules have been replaced by an ipset-matching rule.
	link := []string{
		"-o", bridgeName,
		"-j", DockerChain,
	}
	if iptable.Exists(iptables.Filter, "FORWARD", link...) {
		del := append([]string{string(iptables.Delete), "FORWARD"}, link...)
		if output, err := iptable.Raw(del...); err != nil {
			return err
		} else if len(output) != 0 {
			return fmt.Errorf("could not delete linking rule from %s-%s: %s", iptables.Filter, DockerChain, output)
		}
	}

	// Delete legacy per-bridge related/established rule if it exists. These rules
	// have been replaced by an ipset-matching rule.
	establish := []string{
		"-o", bridgeName,
		"-m", "conntrack",
		"--ctstate", "RELATED,ESTABLISHED",
		"-j", "ACCEPT",
	}
	if iptable.Exists(iptables.Filter, "FORWARD", establish...) {
		del := append([]string{string(iptables.Delete), "FORWARD"}, establish...)
		if output, err := iptable.Raw(del...); err != nil {
			return err
		} else if len(output) != 0 {
			return fmt.Errorf("could not delete establish rule from %s-%s: %s", iptables.Filter, DockerChain, output)
		}
	}

	return nil
}

func (n *bridgeNetwork) setDefaultForwardRule(
	ipVersion iptables.IPVersion,
	bridgeName string,
) error {
	// Normally, DROP anything that hasn't been ACCEPTed by a per-port/protocol
	// rule. This prevents direct access to un-mapped ports from remote hosts
	// that can route directly to the container's address (by setting up a
	// route via the host's address).
	action := "DROP"
	if n.gwMode(ipVersion).unprotected() {
		// If the user really wants to allow all access from the wider network,
		// explicitly ACCEPT anything so that the filter-FORWARD chain's
		// default policy can't interfere.
		action = "ACCEPT"
	}

	rule := iptables.Rule{IPVer: ipVersion, Table: iptables.Filter, Chain: DockerChain, Args: []string{
		"!", "-i", bridgeName,
		"-o", bridgeName,
		"-j", action,
	}}

	// Append to the filter table's DOCKER chain (the default rule must follow
	// per-port ACCEPT rules, which will be inserted at the top of the chain).
	if err := appendOrDelChainRule(rule, "DEFAULT FWD", true); err != nil {
		return fmt.Errorf("failed to add default-drop rule: %w", err)
	}
	n.registerIptCleanFunc(func() error {
		return appendOrDelChainRule(rule, "DEFAULT FWD", false)
	})
	return nil
}

func setupNonInternalNetworkRules(ipVer iptables.IPVersion, config pktfilter.NetworkConfigFam, hairpin, enable bool) error {
	var natArgs, hpNatArgs []string
	if config.HostIP.IsValid() {
		// The user wants IPv4/IPv6 SNAT with the given address.
		hostAddr := config.HostIP.String()
		natArgs = []string{"-s", addr.String(), "!", "-o", config.BridgeName, "-j", "SNAT", "--to-source", hostAddr}
		hpNatArgs = []string{"-m", "addrtype", "--src-type", "LOCAL", "-o", config.BridgeName, "-j", "SNAT", "--to-source", hostAddr}
	} else {
		// Use MASQUERADE, which picks the src-ip based on next-hop from the route table
		natArgs = []string{"-s", addr.String(), "!", "-o", config.BridgeName, "-j", "MASQUERADE"}
		hpNatArgs = []string{"-m", "addrtype", "--src-type", "LOCAL", "-o", config.BridgeName, "-j", "MASQUERADE"}
	}
	natRule := iptables.Rule{IPVer: ipVer, Table: iptables.Nat, Chain: "POSTROUTING", Args: natArgs}
	hpNatRule := iptables.Rule{IPVer: ipVer, Table: iptables.Nat, Chain: "POSTROUTING", Args: hpNatArgs}

	// Set NAT.
	nat := !config.Routed
	if nat && config.EnableIPMasquerade {
		if err := programChainRule(natRule, "NAT", enable); err != nil {
			return err
		}
	}
	if !nat || (config.EnableIPMasquerade && !hairpin) {
		skipDNAT := iptables.Rule{IPVer: ipVer, Table: iptables.Nat, Chain: DockerChain, Args: []string{
			"-i", config.BridgeName,
			"-j", "RETURN",
		}}
		if err := programChainRule(skipDNAT, "SKIP DNAT", enable); err != nil {
			return err
		}
	}

	// In hairpin mode, masquerade traffic from localhost. If hairpin is disabled or if we're tearing down
	// that bridge, make sure the iptables rule isn't lying around.
	if err := programChainRule(hpNatRule, "MASQ LOCAL HOST", enable && hairpin); err != nil {
		return err
	}

	// Set Inter Container Communication.
	if err := setIcc(ipVer, config.BridgeName, config.EnableICC, false, enable); err != nil {
		return err
	}

	// Allow ICMP in routed mode.
	if !nat {
		if err := setICMP(ipVer, config.BridgeName, enable); err != nil {
			return err
		}
	}

	// Handle outgoing packets. This rule was previously added unconditionally
	// to ACCEPT packets that weren't ICC - an extra rule was needed to enable
	// ICC if needed. Those rules are now combined. So, outRuleNoICC is only
	// needed for ICC=false, along with the DROP rule for ICC added by setIcc.
	outRuleNoICC := iptables.Rule{IPVer: ipVer, Table: iptables.Filter, Chain: "FORWARD", Args: []string{
		"-i", config.BridgeName,
		"!", "-o", config.BridgeName,
		"-j", "ACCEPT",
	}}
	if config.EnableICC {
		// Remove the legacy rule for ICC (which didn't accept outgoing traffic), if one has been
		// left behind by an old daemon.
		if err := outRuleNoICC.Delete(); err != nil {
			return err
		}
		// Accept outgoing traffic to anywhere, including other containers on this bridge.
		outRuleICC := iptables.Rule{IPVer: ipVer, Table: iptables.Filter, Chain: "FORWARD", Args: []string{
			"-i", config.BridgeName,
			"-j", "ACCEPT",
		}}
		if err := appendOrDelChainRule(outRuleICC, "ACCEPT OUTGOING", enable); err != nil {
			return err
		}
	} else {
		// Accept outgoing traffic to anywhere, apart from other containers on this bridge.
		// setIcc added a DROP rule for ICC traffic.
		if err := appendOrDelChainRule(outRuleNoICC, "ACCEPT NON_ICC OUTGOING", enable); err != nil {
			return err
		}
	}

	return nil
}

func setIcc(version iptables.IPVersion, bridgeIface string, iccEnable, internal, insert bool) error {
	args := []string{"-i", bridgeIface, "-o", bridgeIface, "-j"}
	acceptRule := iptables.Rule{IPVer: version, Table: iptables.Filter, Chain: "FORWARD", Args: append(args, "ACCEPT")}
	dropRule := iptables.Rule{IPVer: version, Table: iptables.Filter, Chain: "FORWARD", Args: append(args, "DROP")}

	// The accept rule is no longer required for a bridge with external connectivity, because
	// ICC traffic is allowed by the outgoing-packets rule created by setupIptablesInternal.
	// The accept rule is still required for a --internal network because it has no outgoing
	// rule. If insert and the rule is not required, an ACCEPT rule for an external network
	// may have been left behind by an older version of the daemon so, delete it.
	if insert && iccEnable && internal {
		if err := acceptRule.Append(); err != nil {
			return fmt.Errorf("Unable to allow intercontainer communication: %w", err)
		}
	} else {
		if err := acceptRule.Delete(); err != nil {
			log.G(context.TODO()).WithError(err).Warn("Failed to delete legacy ICC accept rule")
		}
	}

	if insert && !iccEnable {
		if err := dropRule.Append(); err != nil {
			return fmt.Errorf("Unable to prevent intercontainer communication: %w", err)
		}
	} else {
		if err := dropRule.Delete(); err != nil {
			log.G(context.TODO()).WithError(err).Warn("Failed to delete ICC drop rule")
		}
	}
	return nil
}

// Control Inter-Network Communication.
// Install rules only if they aren't present, remove only if they are.
// If this method returns an error, it doesn't roll back any rules it has added.
// No error is returned if rules cannot be removed (errors are just logged).
func setINC(version iptables.IPVersion, iface string, gwm gwMode, enable bool) (retErr error) {
	iptable := iptables.GetIptable(version)
	actionI, actionA := iptables.Insert, iptables.Append
	actionMsg := "add"
	if !enable {
		actionI, actionA = iptables.Delete, iptables.Delete
		actionMsg = "remove"
	}

	if gwm.routed() {
		// Anything is allowed into a routed network at this stage, so RETURN. Port
		// filtering rules in the DOCKER chain will drop anything that's not destined
		// for an open port.
		if err := iptable.ProgramRule(iptables.Filter, IsolationChain1, actionI, []string{
			"-o", iface,
			"-j", "RETURN",
		}); err != nil {
			log.G(context.TODO()).WithError(err).Warnf("Failed to %s inter-network communication rule", actionMsg)
			if enable {
				return fmt.Errorf("%s inter-network communication rule: %w", actionMsg, err)
			}
		}

		// Allow responses from the routed network into whichever network made the request.
		if err := iptable.ProgramRule(iptables.Filter, IsolationChain1, actionI, []string{
			"-i", iface,
			"-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED",
			"-j", "ACCEPT",
		}); err != nil {
			log.G(context.TODO()).WithError(err).Warnf("Failed to %s inter-network communication rule", actionMsg)
			if enable {
				return fmt.Errorf("%s inter-network communication rule: %w", actionMsg, err)
			}
		}
	}

	if err := iptable.ProgramRule(iptables.Filter, IsolationChain1, actionA, []string{
		"-i", iface,
		"!", "-o", iface,
		"-j", IsolationChain2,
	}); err != nil {
		log.G(context.TODO()).WithError(err).Warnf("Failed to %s inter-network communication rule", actionMsg)
		if enable {
			return fmt.Errorf("%s inter-network communication rule: %w", actionMsg, err)
		}
	}

	if err := iptable.ProgramRule(iptables.Filter, IsolationChain2, actionI, []string{
		"-o", iface,
		"-j", "DROP",
	}); err != nil {
		log.G(context.TODO()).WithError(err).Warnf("Failed to %s inter-network communication rule", actionMsg)
		if enable {
			return fmt.Errorf("%s inter-network communication rule: %w", actionMsg, err)
		}
	}

	return nil
}

func setupInternalNetworkRules(bridgeIface string, prefix netip.Prefix, icc, insert bool) error {
	var version iptables.IPVersion
	var inDropRule, outDropRule iptables.Rule

	// Either add or remove the interface from the firewalld zone, if firewalld is running.
	if insert {
		if err := iptables.AddInterfaceFirewalld(bridgeIface); err != nil {
			return err
		}
	} else {
		if err := iptables.DelInterfaceFirewalld(bridgeIface); err != nil && !errdefs.IsNotFound(err) {
			return err
		}
	}

	if prefix.Addr().Is4() {
		version = iptables.IPv4
		inDropRule = iptables.Rule{
			IPVer: version,
			Table: iptables.Filter,
			Chain: IsolationChain1,
			Args:  []string{"-i", bridgeIface, "!", "-d", prefix.String(), "-j", "DROP"},
		}
		outDropRule = iptables.Rule{
			IPVer: version,
			Table: iptables.Filter,
			Chain: IsolationChain1,
			Args:  []string{"-o", bridgeIface, "!", "-s", prefix.String(), "-j", "DROP"},
		}
	} else {
		version = iptables.IPv6
		inDropRule = iptables.Rule{
			IPVer: version,
			Table: iptables.Filter,
			Chain: IsolationChain1,
			Args:  []string{"-i", bridgeIface, "!", "-o", bridgeIface, "!", "-d", prefix.String(), "-j", "DROP"},
		}
		outDropRule = iptables.Rule{
			IPVer: version,
			Table: iptables.Filter,
			Chain: IsolationChain1,
			Args:  []string{"!", "-i", bridgeIface, "-o", bridgeIface, "!", "-s", prefix.String(), "-j", "DROP"},
		}
	}

	if err := programChainRule(inDropRule, "DROP INCOMING", insert); err != nil {
		return err
	}
	if err := programChainRule(outDropRule, "DROP OUTGOING", insert); err != nil {
		return err
	}

	// Set Inter Container Communication.
	return setIcc(version, bridgeIface, icc, true, insert)
}

// clearConntrackEntries flushes conntrack entries matching endpoint IP address
// or matching one of the exposed UDP port.
// In the first case, this could happen if packets were received by the host
// between userland proxy startup and iptables setup.
// In the latter case, this could happen if packets were received whereas there
// were nowhere to route them, as netfilter creates entries in such case.
// This is required because iptables NAT rules are evaluated by netfilter only
// when creating a new conntrack entry. When Docker latter adds NAT rules,
// netfilter ignore them for any packet matching a pre-existing conntrack entry.
// As such, we need to flush all those conntrack entries to make sure NAT rules
// are correctly applied to all packets.
// See: #8795, #44688 & #44742.
func clearConntrackEntries(nlh nlwrap.Handle, ep *bridgeEndpoint) {
	var ipv4List []net.IP
	var ipv6List []net.IP
	var udpPorts []uint16

	if ep.addr != nil {
		ipv4List = append(ipv4List, ep.addr.IP)
	}
	if ep.addrv6 != nil {
		ipv6List = append(ipv6List, ep.addrv6.IP)
	}
	for _, pb := range ep.portMapping {
		if pb.Proto == types.UDP {
			udpPorts = append(udpPorts, pb.HostPort)
		}
	}

	iptables.DeleteConntrackEntries(nlh, ipv4List, ipv6List)
	iptables.DeleteConntrackEntriesByPort(nlh, types.UDP, udpPorts)
}
