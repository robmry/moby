package nftabler

import (
	"context"
	"errors"
	"fmt"

	"github.com/containerd/log"
	"github.com/docker/docker/libnetwork/drivers/bridge/internal/firewaller"
	"github.com/docker/docker/libnetwork/internal/nftables"
	"go.opentelemetry.io/otel"
)

type network struct {
	firewaller.NetworkConfig
	fw *nftabler
}

func (nft *nftabler) NewNetwork(ctx context.Context, nc firewaller.NetworkConfig) (_ firewaller.Network, retErr error) {
	n := &network{
		fw:            nft,
		NetworkConfig: nc,
	}
	defer func() {
		if retErr != nil {
			n.DelNetworkLevelRules(ctx)
		}
	}()

	if n.fw.IPv4 {
		if err := n.configure(ctx, nft.table4, n.Config4); err != nil {
			return nil, err
		}
	}
	if n.fw.IPv6 {
		if err := n.configure(ctx, nft.table6, n.Config6); err != nil {
			return nil, err
		}
	}
	return n, nil
}

func (n *network) configure(ctx context.Context, table nftables.TableRef, conf firewaller.NetworkConfigFam) error {
	ctx, span := otel.Tracer("").Start(ctx, spanPrefix+".newNetwork."+string(table.Family()))
	defer span.End()

	if !conf.Prefix.IsValid() {
		return nil
	}

	// Filter chain
	fwdInChain := table.Chain(chainFilterFwdIn(n.IfName))
	fwdOutChain := table.Chain(chainFilterFwdOut(n.IfName))
	if err := table.InterfaceVMap(filtFwdInVMap).AddElement(n.IfName, "jump "+chainFilterFwdIn(n.IfName)); err != nil {
		return fmt.Errorf("adding filter-forward jump for %s to %q: %w", conf.Prefix, chainFilterFwdIn(n.IfName), err)
	}
	if err := table.InterfaceVMap(filtFwdOutVMap).AddElement(n.IfName, "jump "+chainFilterFwdOut(n.IfName)); err != nil {
		return fmt.Errorf("adding filter-forward jump for %s to %q: %w", conf.Prefix, chainFilterFwdOut(n.IfName), err)
	}
	if err := table.PrefixSet(networkPrefixSet).AddElement(conf.Prefix.String()); err != nil {
		return fmt.Errorf("adding %s to network set for %q: %w", conf.Prefix, n.IfName, err)
	}

	// NAT chain
	natPostroutingIn := table.Chain(chainNatPostRtIn(n.IfName))
	if err := table.InterfaceVMap(natPostroutingInVMap).AddElement(n.IfName, "jump "+chainNatPostRtIn(n.IfName)); err != nil {
		return fmt.Errorf("adding postrouting in jump for %s to %q: %w", conf.Prefix, chainNatPostRtIn(n.IfName), err)
	}
	natPostroutingOut := table.Chain(chainNatPostRtOut(n.IfName))
	if err := table.InterfaceVMap(natPostroutingOutVMap).AddElement(n.IfName, "jump "+chainNatPostRtOut(n.IfName)); err != nil {
		return fmt.Errorf("adding postrouting out jump for %s to %q: %w", conf.Prefix, chainNatPostRtOut(n.IfName), err)
	}

	// Conntrack
	if err := fwdInChain.AppendRule(initialRuleGroup, "ct state established,related counter accept"); err != nil {
		return fmt.Errorf("adding conntrack in rule for %q: %w", n.IfName, err)
	}
	if err := fwdOutChain.AppendRule(initialRuleGroup, "ct state established,related counter accept"); err != nil {
		return fmt.Errorf("adding conntrack out rule for %q: %w", n.IfName, err)
	}

	if n.Internal {
		if err := fwdInChain.AppendRule(initialRuleGroup,
			`iifname != %s counter drop comment "INTERNAL NETWORK"`, n.IfName); err != nil {
			return fmt.Errorf("adding INTERNAL NETWORK in rule for %q: %w", n.IfName, err)
		}
		if err := fwdOutChain.AppendRule(initialRuleGroup,
			`oifname != %s counter drop comment "INTERNAL NETWORK"`, n.IfName); err != nil {
			return fmt.Errorf("adding INTERNAL NETWORK out rule for %q: %w", n.IfName, err)
		}
	} else {
		// Inter-Container Communication
		iccVerdict := "accept"
		if !n.ICC {
			iccVerdict = "drop"
		}
		if err := fwdInChain.AppendRule(fwdInICCRuleGroup, "iifname == %s counter %s comment ICC",
			n.IfName, iccVerdict); err != nil {
			return fmt.Errorf("adding ICC rule for %q: %w", n.IfName, err)
		}

		// Inter-Network Communication
		nat := !conf.Routed
		if false && nat {
			// Drop packets from other bridge networks.
			//
			// TODO(robmry) - maybe drop this and allow from any other network? The INC rules aren't useful now ports are filtered?
			//  - if not, need to migrate the "skip dnat" behaviour from iptables
			if err := fwdInChain.AppendRule(initialRuleGroup,
				"%[1]s saddr != %[2]s %[1]s saddr @"+networkPrefixSet+" counter drop comment INC",
				table.Family(), conf.Prefix); err != nil {
				return fmt.Errorf("adding INC rule for %q: %w", n.IfName, err)
			}
		}

		// Outgoing traffic
		if err := fwdOutChain.AppendRule(initialRuleGroup, "counter accept comment OUTGOING"); err != nil {
			return fmt.Errorf("adding OUTGOING rule for %q: %w", n.IfName, err)
		}

		// Incoming traffic
		if conf.Unprotected {
			if err := fwdInChain.AppendRule(fwdInFinalRuleGroup, `counter accept comment "UNPROTECTED"`); err != nil {
				return fmt.Errorf("adding UNPROTECTED for %q: %w", n.IfName, err)
			}
		} else {
			if err := fwdInChain.AppendRule(fwdInFinalRuleGroup, `counter drop comment "UNPUBLISHED PORT DROP"`); err != nil {
				return fmt.Errorf("adding UNPUBLISHED PORT DROP for %q: %w", n.IfName, err)
			}
		}

		// ICMP
		if conf.Routed {
			rule := "ip protocol icmp"
			if table.Family() == nftables.IPv6 {
				rule = "meta l4proto ipv6-icmp"
			}
			if err := fwdInChain.AppendRule(initialRuleGroup, rule+" counter accept comment ICMP"); err != nil {
				return fmt.Errorf("adding ICMP rule for %q: %w", n.IfName, err)
			}
		}

		// Masquerade / SNAT - masquerade picks a source IP address based on next-hop, SNAT uses conf.HostIP.
		natPostroutingVerdict := "masquerade"
		natPostroutingComment := "MASQUERADE"
		if conf.HostIP.IsValid() {
			natPostroutingVerdict = "snat to " + conf.HostIP.Unmap().String()
			natPostroutingComment = "SNAT"
		}
		if n.Masquerade && nat {
			if err := natPostroutingOut.AppendRule(initialRuleGroup, `oifname != %s %s saddr %s counter %s comment "%s"`,
				n.IfName, table.Family(), conf.Prefix, natPostroutingVerdict, natPostroutingComment); err != nil {
				return fmt.Errorf("adding NAT rule for %q: %w", n.IfName, err)
			}
		}
		if n.fw.Hairpin {
			// Masquerade/SNAT traffic from localhost.
			if err := natPostroutingIn.AppendRule(initialRuleGroup, `fib saddr type local counter %s comment "%s FROM HOST"`,
				natPostroutingVerdict, natPostroutingComment); err != nil {
				return fmt.Errorf("adding NAT local rule for %q: %w", n.IfName, err)
			}
		}
	}

	ctx = log.WithLogger(ctx, log.G(ctx).WithFields(log.Fields{
		"bridge": n.IfName,
		"family": table.Family(),
	}))
	if err := nftApply(ctx, table); err != nil {
		return fmt.Errorf("adding rules for bridge %s: %w", n.IfName, err)
	}

	return nil
}

func (n *network) ReapplyNetworkLevelRules(ctx context.Context) error {
	log.G(ctx).Warn("ReapplyNetworkLevelRules is not implemented for nftables")
	return nil
}

func (n *network) DelNetworkLevelRules(ctx context.Context) error {
	var errs []error
	if n.fw.IPv4 && n.Config4.Prefix.IsValid() {
		n.cleanupFam(ctx, n.fw.table4, n.Config4)
	}
	if n.fw.IPv6 && n.Config6.Prefix.IsValid() {
		n.cleanupFam(ctx, n.fw.table6, n.Config6)
	}
	return errors.Join(errs...)
}

func (n *network) cleanupFam(ctx context.Context, table nftables.TableRef, conf firewaller.NetworkConfigFam) {
	ctx = log.WithLogger(ctx, log.G(ctx).WithFields(log.Fields{
		"bridge": n.IfName,
		"family": table.Family(),
	}))

	// Filter forward chain
	if err := table.InterfaceVMap(filtFwdInVMap).DeleteElement(n.IfName); err != nil {
		log.G(ctx).WithError(err).Debug("Deleting filter-forward dest jump")
	}
	if err := table.InterfaceVMap(filtFwdOutVMap).DeleteElement(n.IfName); err != nil {
		log.G(ctx).WithError(err).Debug("Deleting filter-forward dest jump")
	}
	if err := table.PrefixSet(networkPrefixSet).DeleteElement(conf.Prefix.String()); err != nil {
		log.G(ctx).WithError(err).Debug("Deleting network from net prefix set")
	}
	if err := table.DeleteChain(chainFilterFwdIn(n.IfName)); err != nil {
		log.G(ctx).WithError(err).Debug("Deleting chain")
	}
	if err := table.DeleteChain(chainFilterFwdOut(n.IfName)); err != nil {
		log.G(ctx).WithError(err).Debug("Deleting chain")
	}

	// NAT postrouting chain
	if err := table.InterfaceVMap(natPostroutingOutVMap).DeleteElement(n.IfName); err != nil {
		log.G(ctx).WithError(err).Debug("Deleting nat-postrouting out jump")
	}
	if err := table.InterfaceVMap(natPostroutingInVMap).DeleteElement(n.IfName); err != nil {
		log.G(ctx).WithError(err).Debug("Deleting nat-postrouting in jump")
	}
	if err := table.DeleteChain(chainNatPostRtOut(n.IfName)); err != nil {
		log.G(ctx).WithError(err).Debug("Deleting postrouting out chain")
	}
	if err := table.DeleteChain(chainNatPostRtIn(n.IfName)); err != nil {
		log.G(ctx).WithError(err).Debug("Deleting postrouting in chain")
	}

	if err := nftApply(ctx, table); err != nil {
		log.G(ctx).WithError(err).Warn("Failed to remove nftables rules")
	}
}

func chainFilterFwdIn(ifName string) string {
	return "filter-forward-in__" + ifName
}

func chainFilterFwdOut(ifName string) string {
	return "filter-forward-out__" + ifName
}

func chainNatPostRtOut(ifName string) string {
	return "nat-postrouting-out__" + ifName
}

func chainNatPostRtIn(ifName string) string {
	return "nat-postrouting-in__" + ifName
}
