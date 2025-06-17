//go:build linux

package nftabler

import (
	"context"
	"fmt"

	"github.com/containerd/log"
	"github.com/docker/docker/libnetwork/drivers/bridge/internal/firewaller"
	"github.com/docker/docker/libnetwork/internal/nftables"
	"go.opentelemetry.io/otel"
)

type network struct {
	config      firewaller.NetworkConfig
	cleanFuncs4 []func() error
	cleanFuncs6 []func() error
	fw          *nftabler
	ports       *portRulers
}

func (nft *nftabler) NewNetwork(ctx context.Context, nc firewaller.NetworkConfig) (_ firewaller.Network, retErr error) {
	n := &network{
		fw:     nft,
		config: nc,
		ports:  newPortRulers(),
	}
	defer func() {
		if retErr != nil {
			if err := n.DelNetworkLevelRules(ctx); err != nil {
				log.G(ctx).WithError(err).Error("Ignoring cleanup error")
			}
		}
	}()

	if nft.cleaner != nil {
		nft.cleaner.DelNetwork(ctx, nc)
	}

	if n.fw.config.IPv4 {
		var err error
		n.cleanFuncs4, err = n.configure(ctx, nft.table4, n.config.Config4)
		if err != nil {
			return nil, err
		}
	}
	if n.fw.config.IPv6 {
		var err error
		n.cleanFuncs6, err = n.configure(ctx, nft.table6, n.config.Config6)
		if err != nil {
			return nil, err
		}
	}
	return n, nil
}

func (n *network) configure(ctx context.Context, table nftables.TableRef, conf firewaller.NetworkConfigFam) (_ []func() error, retErr error) {
	ctx, span := otel.Tracer("").Start(ctx, spanPrefix+".newNetwork."+string(table.Family()))
	defer span.End()

	if !conf.Prefix.IsValid() {
		return nil, nil
	}

	var cleanFuncs []func() error
	defer func() {
		if retErr != nil {
			cleanup(ctx, cleanFuncs, table)
		}
	}()

	// Filter chain

	fwdInChain := table.Chain(chainFilterFwdIn(n.config.IfName))
	cleanFuncs = append(cleanFuncs, func() error { return table.DeleteChain(chainFilterFwdIn(n.config.IfName)) })
	fwdOutChain := table.Chain(chainFilterFwdOut(n.config.IfName))
	cleanFuncs = append(cleanFuncs, func() error { return table.DeleteChain(chainFilterFwdOut(n.config.IfName)) })

	cf, err := table.InterfaceVMap(filtFwdInVMap).AddElementUf(n.config.IfName, "jump "+chainFilterFwdIn(n.config.IfName))
	if err != nil {
		return nil, fmt.Errorf("adding filter-forward jump for %s to %q: %w", conf.Prefix, chainFilterFwdIn(n.config.IfName), err)
	}
	cleanFuncs = append(cleanFuncs, cf)

	cf, err = table.InterfaceVMap(filtFwdOutVMap).AddElementUf(n.config.IfName, "jump "+chainFilterFwdOut(n.config.IfName))
	if err != nil {
		return nil, fmt.Errorf("adding filter-forward jump for %s to %q: %w", conf.Prefix, chainFilterFwdOut(n.config.IfName), err)
	}
	cleanFuncs = append(cleanFuncs, cf)

	// NAT chain

	natPostroutingIn := table.Chain(chainNatPostRtIn(n.config.IfName))
	cleanFuncs = append(cleanFuncs, func() error { return table.DeleteChain(chainNatPostRtIn(n.config.IfName)) })
	cf, err = table.InterfaceVMap(natPostroutingInVMap).AddElementUf(n.config.IfName, "jump "+chainNatPostRtIn(n.config.IfName))
	if err != nil {
		return nil, fmt.Errorf("adding postrouting ingress jump for %s to %q: %w", conf.Prefix, chainNatPostRtIn(n.config.IfName), err)
	}
	cleanFuncs = append(cleanFuncs, cf)

	natPostroutingOut := table.Chain(chainNatPostRtOut(n.config.IfName))
	cleanFuncs = append(cleanFuncs, func() error { return table.DeleteChain(chainNatPostRtOut(n.config.IfName)) })
	cf, err = table.InterfaceVMap(natPostroutingOutVMap).AddElementUf(n.config.IfName, "jump "+chainNatPostRtOut(n.config.IfName))
	if err != nil {
		return nil, fmt.Errorf("adding postrouting egress jump for %s to %q: %w", conf.Prefix, chainNatPostRtOut(n.config.IfName), err)
	}
	cleanFuncs = append(cleanFuncs, cf)

	// Conntrack

	cf, err = fwdInChain.AppendRuleUf(initialRuleGroup, "ct state established,related counter accept")
	if err != nil {
		return nil, fmt.Errorf("adding conntrack ingress rule for %q: %w", n.config.IfName, err)
	}
	cleanFuncs = append(cleanFuncs, cf)

	cf, err = fwdOutChain.AppendRuleUf(initialRuleGroup, "ct state established,related counter accept")
	if err != nil {
		return nil, fmt.Errorf("adding conntrack egress rule for %q: %w", n.config.IfName, err)
	}
	cleanFuncs = append(cleanFuncs, cf)

	iccVerdict := "accept"
	if !n.config.ICC {
		iccVerdict = "drop"
	}

	if n.config.Internal {
		// Drop anything that's not from this network.
		cf, err = fwdInChain.AppendRuleUf(initialRuleGroup,
			`iifname != %s counter drop comment "INTERNAL NETWORK INGRESS"`, n.config.IfName)
		if err != nil {
			return nil, fmt.Errorf("adding INTERNAL NETWORK ingress rule for %q: %w", n.config.IfName, err)
		}
		cleanFuncs = append(cleanFuncs, cf)

		cf, err = fwdOutChain.AppendRuleUf(initialRuleGroup,
			`oifname != %s counter drop comment "INTERNAL NETWORK EGRESS"`, n.config.IfName)
		if err != nil {
			return nil, fmt.Errorf("adding INTERNAL NETWORK egress rule for %q: %w", n.config.IfName, err)
		}
		cleanFuncs = append(cleanFuncs, cf)

		// Accept or drop Inter-Container Communication.
		cf, err = fwdInChain.AppendRuleUf(fwdInICCRuleGroup, "counter %s comment ICC", iccVerdict)
		if err != nil {
			return nil, fmt.Errorf("adding ICC ingress rule for %q: %w", n.config.IfName, err)
		}
		cleanFuncs = append(cleanFuncs, cf)
	} else {
		// Inter-Container Communication
		cf, err = fwdInChain.AppendRuleUf(fwdInICCRuleGroup, "iifname == %s counter %s comment ICC",
			n.config.IfName, iccVerdict)
		if err != nil {
			return nil, fmt.Errorf("adding ICC rule for %q: %w", n.config.IfName, err)
		}
		cleanFuncs = append(cleanFuncs, cf)

		// Outgoing traffic
		cf, err = fwdOutChain.AppendRuleUf(initialRuleGroup, "counter accept comment OUTGOING")
		if err != nil {
			return nil, fmt.Errorf("adding OUTGOING rule for %q: %w", n.config.IfName, err)
		}
		cleanFuncs = append(cleanFuncs, cf)

		// Incoming traffic
		if conf.Unprotected {
			cf, err = fwdInChain.AppendRuleUf(fwdInFinalRuleGroup, `counter accept comment "UNPROTECTED"`)
			if err != nil {
				return nil, fmt.Errorf("adding UNPROTECTED for %q: %w", n.config.IfName, err)
			}
			cleanFuncs = append(cleanFuncs, cf)
		} else {
			cf, err = fwdInChain.AppendRuleUf(fwdInFinalRuleGroup, `counter drop comment "UNPUBLISHED PORT DROP"`)
			if err != nil {
				return nil, fmt.Errorf("adding UNPUBLISHED PORT DROP for %q: %w", n.config.IfName, err)
			}
			cleanFuncs = append(cleanFuncs, cf)
		}

		// ICMP
		if conf.Routed {
			rule := "ip protocol icmp"
			if table.Family() == nftables.IPv6 {
				rule = "meta l4proto ipv6-icmp"
			}
			cf, err = fwdInChain.AppendRuleUf(initialRuleGroup, rule+" counter accept comment ICMP")
			if err != nil {
				return nil, fmt.Errorf("adding ICMP rule for %q: %w", n.config.IfName, err)
			}
			cleanFuncs = append(cleanFuncs, cf)
		}

		// Masquerade / SNAT - masquerade picks a source IP address based on next-hop, SNAT uses conf.HostIP.
		natPostroutingVerdict := "masquerade"
		natPostroutingComment := "MASQUERADE"
		if conf.HostIP.IsValid() {
			natPostroutingVerdict = "snat to " + conf.HostIP.Unmap().String()
			natPostroutingComment = "SNAT"
		}
		if n.config.Masquerade && !conf.Routed {
			cf, err = natPostroutingOut.AppendRuleUf(initialRuleGroup, `oifname != %s %s saddr %s counter %s comment "%s"`,
				n.config.IfName, table.Family(), conf.Prefix, natPostroutingVerdict, natPostroutingComment)
			if err != nil {
				return nil, fmt.Errorf("adding NAT rule for %q: %w", n.config.IfName, err)
			}
			cleanFuncs = append(cleanFuncs, cf)
		}
		if n.fw.config.Hairpin {
			// Masquerade/SNAT traffic from localhost.
			cf, err = natPostroutingIn.AppendRuleUf(initialRuleGroup, `fib saddr type local counter %s comment "%s FROM HOST"`,
				natPostroutingVerdict, natPostroutingComment)
			if err != nil {
				return nil, fmt.Errorf("adding NAT local rule for %q: %w", n.config.IfName, err)
			}
			cleanFuncs = append(cleanFuncs, cf)
		}
	}

	ctx = log.WithLogger(ctx, log.G(ctx).WithFields(log.Fields{
		"bridge": n.config.IfName,
		"family": table.Family(),
	}))
	if err := nftApply(ctx, table); err != nil {
		return nil, fmt.Errorf("adding rules for bridge %s: %w", n.config.IfName, err)
	}

	return cleanFuncs, nil
}

func (n *network) ReapplyNetworkLevelRules(ctx context.Context) error {
	// A firewalld reload doesn't delete nftables rules, this function is not needed.
	log.G(ctx).Warn("ReapplyNetworkLevelRules is not implemented for nftables")
	return nil
}

func (n *network) DelNetworkLevelRules(ctx context.Context) error {
	ctx = log.WithLogger(ctx, log.G(ctx).WithFields(log.Fields{"bridge": n.config.IfName}))
	cleanup(ctx, n.cleanFuncs4, n.fw.table4)
	n.cleanFuncs4 = nil
	cleanup(ctx, n.cleanFuncs6, n.fw.table6)
	n.cleanFuncs6 = nil
	return nil
}

func cleanup(ctx context.Context, cfs []func() error, table nftables.TableRef) {
	if len(cfs) == 0 {
		return
	}
	for _, cf := range cfs {
		if err := cf(); err != nil {
			log.G(ctx).WithError(err).Warn("Failed to remove nftables rule")
		}
	}
	if err := nftApply(ctx, table); err != nil {
		log.G(ctx).WithError(err).Warn("Failed to apply update removing nftables rules")
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
