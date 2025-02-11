package iptables

import (
	"context"
	"errors"
	"fmt"
	"net/netip"

	"github.com/containerd/log"
	"github.com/docker/docker/errdefs"
	"github.com/docker/docker/libnetwork/drivers/bridge/internal/pktfilter"
	"github.com/docker/docker/libnetwork/iptables"
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

func (ipt *IPTables) AddNetwork(nc pktfilter.NetworkConfig) (_ pktfilter.Network, retErr error) {
	n := &network{
		NetworkConfig: nc,
		ipt:           ipt,
	}

	defer func() {
		if retErr != nil {
			n.cleanup()
		}
	}()

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

	if !n.Internal {
		if ipt.config.IPv4 {
			n.registerCleanFunc(func() error {
				return setINC(iptables.IPv4, n.IfName, n.Config4.Routed, false)
			})
			if err := setINC(iptables.IPv4, n.IfName, n.Config4.Routed, true); err != nil {
				return nil, err
			}
		}
		if ipt.config.IPv6 {
			n.registerCleanFunc(func() error {
				return setINC(iptables.IPv6, n.IfName, n.Config6.Routed, false)
			})
			if err := setINC(iptables.IPv6, n.IfName, n.Config6.Routed, true); err != nil {
				return nil, err
			}
		}
	}

	return n, nil
}

func (n *network) Delete(_ context.Context) error {
	n.cleanup()
	return nil
}

func (n *network) registerCleanFunc(clean iptableCleanFunc) {
	n.cleanFuncs = append(n.cleanFuncs, clean)
}

func (n *network) cleanup() {
	for _, cleanFunc := range n.cleanFuncs {
		if errClean := cleanFunc(); errClean != nil {
			log.G(context.TODO()).Warnf("Failed to clean iptables rules for bridge network: %v", errClean)
		}
	}
}

func (n *network) setupIPTables(ipVersion iptables.IPVersion, config pktfilter.NetworkConfigFam, ipsetName string) error {
	var err error

	if n.Internal {
		if err = setupInternalNetworkRules(n.IfName, config.Prefix, n.ICC, true); err != nil {
			return fmt.Errorf("Failed to Setup IP tables: %w", err)
		}
		n.registerCleanFunc(func() error {
			return setupInternalNetworkRules(n.IfName, config.Prefix, n.ICC, false)
		})
	} else {
		if err = n.setupNonInternalNetworkRules(ipVersion, config, true); err != nil {
			return fmt.Errorf("Failed to Setup IP tables: %w", err)
		}
		n.registerCleanFunc(func() error {
			return n.setupNonInternalNetworkRules(ipVersion, config, false)
		})

		if err := iptables.AddInterfaceFirewalld(n.IfName); err != nil {
			return err
		}
		n.registerCleanFunc(func() error {
			if err := iptables.DelInterfaceFirewalld(n.IfName); err != nil && !errdefs.IsNotFound(err) {
				return err
			}
			return nil
		})

		err = deleteLegacyFilterRules(ipVersion, n.IfName)
		if err != nil {
			return fmt.Errorf("failed to delete legacy rules in filter-FORWARD: %w", err)
		}

		cf, err := setDefaultForwardRule(ipVersion, n.IfName, config)
		if err != nil {
			return err
		}
		n.registerCleanFunc(cf)

		ipsetEntry := &netlink.IPSetEntry{
			IP:   config.Prefix.Addr().AsSlice(),
			CIDR: uint8(config.Prefix.Bits()),
		}
		if err := netlink.IpsetAdd(ipsetName, ipsetEntry); err != nil {
			if !errors.Is(err, nl.IPSetError(nl.IPSET_ERR_EXIST)) {
				return fmt.Errorf("failed to add bridge %s (%s) to ipset: %w",
					n.IfName, config.Prefix, err)
			}
			log.G(context.TODO()).WithFields(log.Fields{
				"ipset":  ipsetName,
				"bridge": n.IfName,
				"subnet": config.Prefix,
			}).Warnf("Subnet was already in the ipset")
		}
		n.registerCleanFunc(func() error {
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

func setDefaultForwardRule(ipVersion iptables.IPVersion, ifName string, config pktfilter.NetworkConfigFam) (iptableCleanFunc, error) {
	// Normally, DROP anything that hasn't been ACCEPTed by a per-port/protocol
	// rule. This prevents direct access to un-mapped ports from remote hosts
	// that can route directly to the container's address (by setting up a
	// route via the host's address).
	action := "DROP"
	if config.Unprotected {
		// If the user really wants to allow all access from the wider network,
		// explicitly ACCEPT anything so that the filter-FORWARD chain's
		// default policy can't interfere.
		action = "ACCEPT"
	}

	rule := iptables.Rule{IPVer: ipVersion, Table: iptables.Filter, Chain: DockerChain, Args: []string{
		"!", "-i", ifName,
		"-o", ifName,
		"-j", action,
	}}

	// Append to the filter table's DOCKER chain (the default rule must follow
	// per-port ACCEPT rules, which will be inserted at the top of the chain).
	if err := appendOrDelChainRule(rule, "DEFAULT FWD", true); err != nil {
		return nil, fmt.Errorf("failed to add default-drop rule: %w", err)
	}
	return func() error { return appendOrDelChainRule(rule, "DEFAULT FWD", false) }, nil
}

func (n *network) setupNonInternalNetworkRules(ipVer iptables.IPVersion, config pktfilter.NetworkConfigFam, enable bool) error {
	var natArgs, hpNatArgs []string
	if config.HostIP.IsValid() {
		// The user wants IPv4/IPv6 SNAT with the given address.
		hostAddr := config.HostIP.String()
		natArgs = []string{"-s", config.Prefix.String(), "!", "-o", n.IfName, "-j", "SNAT", "--to-source", hostAddr}
		hpNatArgs = []string{"-m", "addrtype", "--src-type", "LOCAL", "-o", n.IfName, "-j", "SNAT", "--to-source", hostAddr}
	} else {
		// Use MASQUERADE, which picks the src-ip based on next-hop from the route table
		natArgs = []string{"-s", config.Prefix.String(), "!", "-o", n.IfName, "-j", "MASQUERADE"}
		hpNatArgs = []string{"-m", "addrtype", "--src-type", "LOCAL", "-o", n.IfName, "-j", "MASQUERADE"}
	}
	natRule := iptables.Rule{IPVer: ipVer, Table: iptables.Nat, Chain: "POSTROUTING", Args: natArgs}
	hpNatRule := iptables.Rule{IPVer: ipVer, Table: iptables.Nat, Chain: "POSTROUTING", Args: hpNatArgs}

	// Set NAT.
	nat := !config.Routed
	hairpin := n.ipt.config.Hairpin
	if nat && n.Masquerade {
		if err := programChainRule(natRule, "NAT", enable); err != nil {
			return err
		}
	}
	if !nat || (n.Masquerade && !hairpin) {
		skipDNAT := iptables.Rule{IPVer: ipVer, Table: iptables.Nat, Chain: DockerChain, Args: []string{
			"-i", n.IfName,
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
	if err := setIcc(ipVer, n.IfName, n.ICC, false, enable); err != nil {
		return err
	}

	// Allow ICMP in routed mode.
	if !nat {
		if err := setICMP(ipVer, n.IfName, enable); err != nil {
			return err
		}
	}

	// Handle outgoing packets. This rule was previously added unconditionally
	// to ACCEPT packets that weren't ICC - an extra rule was needed to enable
	// ICC if needed. Those rules are now combined. So, outRuleNoICC is only
	// needed for ICC=false, along with the DROP rule for ICC added by setIcc.
	outRuleNoICC := iptables.Rule{IPVer: ipVer, Table: iptables.Filter, Chain: "FORWARD", Args: []string{
		"-i", n.IfName,
		"!", "-o", n.IfName,
		"-j", "ACCEPT",
	}}
	if n.ICC {
		// Remove the legacy rule for ICC (which didn't accept outgoing traffic), if one has been
		// left behind by an old daemon.
		if err := outRuleNoICC.Delete(); err != nil {
			return err
		}
		// Accept outgoing traffic to anywhere, including other containers on this bridge.
		outRuleICC := iptables.Rule{IPVer: ipVer, Table: iptables.Filter, Chain: "FORWARD", Args: []string{
			"-i", n.IfName,
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
func setINC(version iptables.IPVersion, iface string, routed, enable bool) (retErr error) {
	iptable := iptables.GetIptable(version)
	actionI, actionA := iptables.Insert, iptables.Append
	actionMsg := "add"
	if !enable {
		actionI, actionA = iptables.Delete, iptables.Delete
		actionMsg = "remove"
	}

	if routed {
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
