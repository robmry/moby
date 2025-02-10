package iptables

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/containerd/log"
	"github.com/docker/docker/internal/modprobe"
	"github.com/docker/docker/internal/nlwrap"
	"github.com/docker/docker/libnetwork/drivers/bridge/internal/pktfilter"
	"github.com/docker/docker/libnetwork/iptables"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	// DockerChain is the DOCKER iptable chain name
	DockerChain = "DOCKER"

	// Obsolete chain from previous docker versions
	oldIsolationChain = "DOCKER-ISOLATION"

	// Isolation between bridge networks is achieved in two stages by means
	// of the following two chains in the filter table. The first chain matches
	// on the source interface being a bridge network's bridge and the
	// destination being a different interface. A positive match leads to the
	// second isolation chain. No match returns to the parent chain. The second
	// isolation chain matches on destination interface being a bridge network's
	// bridge. A positive match identifies a packet originated from one bridge
	// network's bridge destined to another bridge network's bridge and will
	// result in the packet being dropped. No match returns to the parent chain.

	IsolationChain1 = "DOCKER-ISOLATION-STAGE-1"
	IsolationChain2 = "DOCKER-ISOLATION-STAGE-2"

	// ipset names for IPv4 and IPv6 bridge subnets that don't belong
	// to --internal networks.
	ipsetExtBridges4 = "docker-ext-bridges-v4"
	ipsetExtBridges6 = "docker-ext-bridges-v6"
)

// Path to the executable installed in Linux under WSL2 that reports on
// WSL config. https://github.com/microsoft/WSL/releases/tag/2.0.4
// Can be modified by tests.
var wslinfoPath = "/usr/bin/wslinfo"

type IPTables struct {
	config pktfilter.Config
}

func (ipt *IPTables) Init(ctx context.Context, config pktfilter.Config) error {
	ipt.config = config

	if config.IPv4 {
		removeIPChains(ctx, iptables.IPv4)

		if err := setupHashNetIpset(ipsetExtBridges4, unix.AF_INET); err != nil {
			return err
		}
		if err := setupIPChains(ctx, iptables.IPv4, config.Hairpin); err != nil {
			return err
		}

		// Make sure on firewall reload, first thing being re-played is chains creation
		iptables.OnReloaded(func() {
			log.G(ctx).Debugf("Recreating iptables chains on firewall reload")
			if err := setupIPChains(ctx, iptables.IPv4, config.Hairpin); err != nil {
				log.G(context.Background()).WithError(err).Error("Error reloading iptables chains")
			}
		})
	}

	if config.IPv6 {
		if err := modprobe.LoadModules(ctx, func() error {
			iptable := iptables.GetIptable(iptables.IPv6)
			_, err := iptable.Raw("-t", "filter", "-n", "-L", "FORWARD")
			return err
		}, "ip6_tables"); err != nil {
			log.G(ctx).WithError(err).Debug("Loading ip6_tables")
		}

		removeIPChains(ctx, iptables.IPv6)

		if err := setupHashNetIpset(ipsetExtBridges6, unix.AF_INET6); err != nil {
			// Continue, IPv4 will work (as below).
			log.G(ctx).WithError(err).Warn("ip6tables is enabled, but cannot set up IPv6 ipset")
		} else {
			err = setupIPChains(ctx, iptables.IPv6, config.Hairpin)
			if err != nil {
				// If the chains couldn't be set up, it's probably because the kernel has no IPv6
				// support, or it doesn't have module ip6_tables loaded. It won't be possible to
				// create IPv6 networks without enabling ip6_tables in the kernel, or disabling
				// ip6tables in the daemon config. But, allow the daemon to start because IPv4
				// will work. So, log the problem, and continue.
				log.G(ctx).WithError(err).Warn("ip6tables is enabled, but cannot set up ip6tables chains")
			} else {
				// Make sure on firewall reload, first thing being re-played is chains creation
				iptables.OnReloaded(func() {
					log.G(context.Background()).Debugf("Recreating ip6tables chains on firewall reload")
					if err := setupIPChains(ctx, iptables.IPv6, config.Hairpin); err != nil {
						log.G(context.Background()).WithError(err).Error("Error reloading ip6tables chains")
					}
				})
			}
		}
	}

	return nil
}

func (ipt *IPTables) Enabled(version pktfilter.IPVersion) (bool, error) {
	switch version {
	case pktfilter.IPv4:
		return ipt.config.IPv4, nil
	case pktfilter.IPv6:
		return ipt.config.IPv6, nil
	default:
		return false, errors.New("unsupported IP version")
	}
}

func removeIPChains(ctx context.Context, version iptables.IPVersion) {
	ipt := iptables.GetIptable(version)

	// Remove obsolete rules from default chains
	ipt.ProgramRule(iptables.Filter, "FORWARD", iptables.Delete, []string{"-j", oldIsolationChain})

	// Remove chains
	for _, chainInfo := range []iptables.ChainInfo{
		{Name: DockerChain, Table: iptables.Nat, IPVersion: version},
		{Name: DockerChain, Table: iptables.Filter, IPVersion: version},
		{Name: IsolationChain1, Table: iptables.Filter, IPVersion: version},
		{Name: IsolationChain2, Table: iptables.Filter, IPVersion: version},
		{Name: oldIsolationChain, Table: iptables.Filter, IPVersion: version},
	} {
		if err := chainInfo.Remove(); err != nil {
			log.G(ctx).Warnf("Failed to remove existing iptables entries in table %s chain %s : %v", chainInfo.Table, chainInfo.Name, err)
		}
	}
}

func setupHashNetIpset(name string, family uint8) error {
	if err := netlink.IpsetCreate(name, "hash:net", netlink.IpsetCreateOptions{
		Replace: true,
		Family:  family,
	}); err != nil {
		return err
	}
	if err := netlink.IpsetFlush(name); err != nil {
		return err
	}
	return nil
}

func setupIPChains(ctx context.Context, version iptables.IPVersion, hairpin bool) (retErr error) {
	iptable := iptables.GetIptable(version)

	_, err := iptable.NewChain(DockerChain, iptables.Nat)
	if err != nil {
		return fmt.Errorf("failed to create NAT chain %s: %v", DockerChain, err)
	}
	defer func() {
		if retErr != nil {
			if err := iptable.RemoveExistingChain(DockerChain, iptables.Nat); err != nil {
				log.G(ctx).Warnf("failed on removing iptables NAT chain %s on cleanup: %v", DockerChain, err)
			}
		}
	}()

	_, err = iptable.NewChain(DockerChain, iptables.Filter)
	if err != nil {
		return fmt.Errorf("failed to create FILTER chain %s: %v", DockerChain, err)
	}
	defer func() {
		if retErr != nil {
			if err := iptable.RemoveExistingChain(DockerChain, iptables.Filter); err != nil {
				log.G(ctx).Warnf("failed on removing iptables FILTER chain %s on cleanup: %v", DockerChain, err)
			}
		}
	}()

	_, err = iptable.NewChain(IsolationChain1, iptables.Filter)
	if err != nil {
		return fmt.Errorf("failed to create FILTER isolation chain: %v", err)
	}
	defer func() {
		if retErr != nil {
			if err := iptable.RemoveExistingChain(IsolationChain1, iptables.Filter); err != nil {
				log.G(ctx).Warnf("failed on removing iptables FILTER chain %s on cleanup: %v", IsolationChain1, err)
			}
		}
	}()

	_, err = iptable.NewChain(IsolationChain2, iptables.Filter)
	if err != nil {
		return fmt.Errorf("failed to create FILTER isolation chain: %v", err)
	}
	defer func() {
		if retErr != nil {
			if err := iptable.RemoveExistingChain(IsolationChain2, iptables.Filter); err != nil {
				log.G(ctx).Warnf("failed on removing iptables FILTER chain %s on cleanup: %v", IsolationChain2, err)
			}
		}
	}()

	if err := addNATJumpRules(version, hairpin, true); err != nil {
		return fmt.Errorf("failed to add jump rules to %s NAT table: %w", version, err)
	}
	defer func() {
		if retErr != nil {
			if err := addNATJumpRules(version, hairpin, false); err != nil {
				log.G(ctx).Warnf("failed on removing jump rules from %s NAT table: %v", version, err)
			}
		}
	}()

	// Make sure the filter-FORWARD chain has rules to accept related packets and
	// jump to the isolation and docker chains. (Re-)insert at the top of the table,
	// in reverse order.
	ipsetName := ipsetExtBridges4
	if version == iptables.IPv6 {
		ipsetName = ipsetExtBridges6
	}
	if err := iptable.EnsureJumpRule("FORWARD", DockerChain,
		"-m", "set", "--match-set", ipsetName, "dst"); err != nil {
		return err
	}
	if err := iptable.EnsureJumpRule("FORWARD", IsolationChain1); err != nil {
		return err
	}
	if err := iptable.EnsureJumpRule("FORWARD", "ACCEPT",
		"-m", "set", "--match-set", ipsetName, "dst",
		"-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED",
	); err != nil {
		return err
	}

	if err := mirroredWSL2Workaround(ctx, hairpin, version); err != nil {
		return err
	}

	return nil
}

func addNATJumpRules(ipVer iptables.IPVersion, hairpinMode, enable bool) error {
	preroute := iptables.Rule{IPVer: ipVer, Table: iptables.Nat, Chain: "PREROUTING", Args: []string{
		"-m", "addrtype",
		"--dst-type", "LOCAL",
		"-j", DockerChain,
	}}
	if enable {
		if err := preroute.Append(); err != nil {
			return fmt.Errorf("failed to append jump rules to nat-PREROUTING: %s", err)
		}
	} else {
		if err := preroute.Delete(); err != nil {
			return fmt.Errorf("failed to remove jump rules from nat-PREROUTING: %s", err)
		}
	}

	output := iptables.Rule{IPVer: ipVer, Table: iptables.Nat, Chain: "OUTPUT", Args: []string{
		"-m", "addrtype",
		"--dst-type", "LOCAL",
		"-j", DockerChain,
	}}
	if !hairpinMode {
		output.Args = append(output.Args, "!", "--dst", loopbackAddress(ipVer))
	}
	if enable {
		if err := output.Append(); err != nil {
			return fmt.Errorf("failed to append jump rules to nat-OUTPUT: %s", err)
		}
	} else {
		if err := output.Delete(); err != nil {
			return fmt.Errorf("failed to remove jump rules from nat-OUTPUT: %s", err)
		}
	}

	return nil
}

// mirroredWSL2Workaround adds or removes an IPv4 NAT rule, depending on whether
// docker's host Linux appears to be a guest running under WSL2 in with mirrored
// mode networking.
// https://learn.microsoft.com/en-us/windows/wsl/networking#mirrored-mode-networking
//
// Without mirrored mode networking, or for a packet sent from Linux, packets
// sent to 127.0.0.1 are processed as outgoing - they hit the nat-OUTPUT chain,
// which does not jump to the nat-DOCKER chain because the rule has an exception
// for "-d 127.0.0.0/8". The default action on the nat-OUTPUT chain is ACCEPT (by
// default), so the packet is delivered to 127.0.0.1 on lo, where docker-proxy
// picks it up and acts as a man-in-the-middle; it receives the packet and
// re-sends it to the container (or acks a SYN and sets up a second TCP
// connection to the container). So, the container sees packets arrive with a
// source address belonging to the network's bridge, and it is able to reply to
// that address.
//
// In WSL2's mirrored networking mode, Linux has a loopback0 device as well as lo
// (which owns 127.0.0.1 as normal). Packets sent to 127.0.0.1 from Windows to a
// server listening on Linux's 127.0.0.1 are delivered via loopback0, and
// processed as packets arriving from outside the Linux host (which they are).
//
// So, these packets hit the nat-PREROUTING chain instead of nat-OUTPUT. It would
// normally be impossible for a packet ->127.0.0.1 to arrive from outside the
// host, so the nat-PREROUTING jump to nat-DOCKER has no exception for it. The
// packet is processed by a per-bridge DNAT rule in that chain, so it is
// delivered directly to the container (not via docker-proxy) with source address
// 127.0.0.1, so the container can't respond.
//
// DNAT is normally skipped by RETURN rules in the nat-DOCKER chain for packets
// arriving from any other bridge network. Similarly, this function adds (or
// removes) a rule to RETURN early for packets delivered via loopback0 with
// destination 127.0.0.0/8.
func mirroredWSL2Workaround(ctx context.Context, hairpin bool, ipv iptables.IPVersion) error {
	// WSL2 does not (currently) support Windows<->Linux communication via ::1.
	if ipv != iptables.IPv4 {
		return nil
	}
	return programChainRule(mirroredWSL2Rule(), "WSL2 loopback", insertMirroredWSL2Rule(ctx, hairpin))
}

// insertMirroredWSL2Rule returns true if the NAT rule for mirrored WSL2 workaround
// is required. It is required if:
//   - the userland proxy is running. If not, there's nothing on the host to catch
//     the packet, so the loopback0 rule as wouldn't be useful. However, without
//     the workaround, with improvements in WSL2 v2.3.11, and without userland proxy
//     running - no workaround is needed, the normal DNAT/masquerading works.
//   - and, the host Linux appears to be running under Windows WSL2 with mirrored
//     mode networking.
func insertMirroredWSL2Rule(ctx context.Context, hairpin bool) bool {
	if hairpin {
		return false
	}
	return isRunningUnderWSL2MirroredMode(ctx)
}

// isRunningUnderWSL2MirroredMode returns true if the host Linux appears to be
// running under Windows WSL2 with mirrored mode networking. If a loopback0
// device exists, and there's an executable at /usr/bin/wslinfo, infer that
// this is WSL2 with mirrored networking. ("wslinfo --networking-mode" reports
// "mirrored", but applying the workaround for WSL2's loopback device when it's
// not needed is low risk, compared with executing wslinfo with dockerd's
// elevated permissions.)
func isRunningUnderWSL2MirroredMode(ctx context.Context) bool {
	if _, err := nlwrap.LinkByName("loopback0"); err != nil {
		if !errors.As(err, &netlink.LinkNotFoundError{}) {
			log.G(ctx).WithError(err).Warn("Failed to check for WSL interface")
		}
		return false
	}
	stat, err := os.Stat(wslinfoPath)
	if err != nil {
		return false
	}
	return stat.Mode().IsRegular() && (stat.Mode().Perm()&0o111) != 0
}

func mirroredWSL2Rule() iptables.Rule {
	return iptables.Rule{
		IPVer: iptables.IPv4,
		Table: iptables.Nat,
		Chain: DockerChain,
		Args:  []string{"-i", "loopback0", "-d", "127.0.0.0/8", "-j", "RETURN"},
	}
}

// loopbackAddress returns the loopback address for the given IP version.
func loopbackAddress(version iptables.IPVersion) string {
	switch version {
	case iptables.IPv4, "":
		// IPv4 (default for backward-compatibility)
		return "127.0.0.0/8"
	case iptables.IPv6:
		return "::1/128"
	default:
		panic("unknown IP version: " + version)
	}
}

func programChainRule(rule iptables.Rule, ruleDescr string, insert bool) error {
	operation := "disable"
	fn := rule.Delete
	if insert {
		operation = "enable"
		fn = rule.Insert
	}
	if err := fn(); err != nil {
		return fmt.Errorf("Unable to %s %s rule: %w", operation, ruleDescr, err)
	}
	return nil
}

func appendOrDelChainRule(rule iptables.Rule, ruleDescr string, append bool) error {
	operation := "disable"
	fn := rule.Delete
	if append {
		operation = "enable"
		fn = rule.Append
	}
	if err := fn(); err != nil {
		return fmt.Errorf("Unable to %s %s rule: %w", operation, ruleDescr, err)
	}
	return nil
}
