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
	config   firewaller.NetworkConfig
	remover4 nftables.TableModifier
	remover6 nftables.TableModifier
	fw       *nftabler
}

func (nft *nftabler) NewNetwork(ctx context.Context, nc firewaller.NetworkConfig) (_ firewaller.Network, retErr error) {
	n := &network{
		fw:     nft,
		config: nc,
	}
	ctx = log.WithLogger(ctx, log.G(ctx).WithFields(log.Fields{"bridge": n.config.IfName}))

	if nft.cleaner != nil {
		nft.cleaner.DelNetwork(ctx, nc)
	}

	if n.fw.config.IPv4 {
		remover, err := n.configure(ctx, nft.table4, n.config.Config4)
		if err != nil {
			return nil, err
		}
		n.remover4 = remover
	}
	if n.fw.config.IPv6 {
		remover, err := n.configure(ctx, nft.table6, n.config.Config6)
		if err != nil {
			return nil, err
		}
		n.remover6 = remover
	}
	return n, nil
}

func (n *network) configure(ctx context.Context, table nftables.Table, conf firewaller.NetworkConfigFam) (nftables.TableModifier, error) {
	if !conf.Prefix.IsValid() {
		return nftables.TableModifier{}, nil
	}
	tm := table.Modifier()
	ctx, span := otel.Tracer("").Start(ctx, spanPrefix+".newNetwork."+string(tm.Family()))
	defer span.End()

	fwdInChain := chainFilterFwdIn(n.config.IfName)
	fwdOutChain := chainFilterFwdOut(n.config.IfName)
	natPostRtInChain := chainNatPostRtIn(n.config.IfName)
	natPostRtOutChain := chainNatPostRtOut(n.config.IfName)

	// Filter chain

	tm.Create(nftables.ChainDesc{Name: fwdInChain})
	tm.Create(nftables.ChainDesc{Name: fwdOutChain})

	tm.Create(nftables.VMapElementDesc{
		Name:    filtFwdInVMap,
		Key:     n.config.IfName,
		Verdict: "jump " + fwdInChain,
	})
	tm.Create(nftables.VMapElementDesc{
		Name:    filtFwdOutVMap,
		Key:     n.config.IfName,
		Verdict: "jump " + fwdOutChain,
	})

	// NAT chain

	tm.Create(nftables.ChainDesc{Name: natPostRtInChain})
	tm.Create(nftables.VMapElementDesc{
		Name:    natPostroutingInVMap,
		Key:     n.config.IfName,
		Verdict: "jump " + natPostRtInChain,
	})

	tm.Create(nftables.ChainDesc{Name: chainNatPostRtOut(n.config.IfName)})
	tm.Create(nftables.VMapElementDesc{
		Name:    natPostroutingOutVMap,
		Key:     n.config.IfName,
		Verdict: "jump " + chainNatPostRtOut(n.config.IfName),
	})

	// Conntrack

	tm.Create(nftables.RuleDesc{
		Chain: chainFilterFwdIn(n.config.IfName),
		Group: initialRuleGroup,
		Rule:  []string{"ct state established,related counter accept"},
	})
	tm.Create(nftables.RuleDesc{
		Chain: chainFilterFwdOut(n.config.IfName),
		Group: initialRuleGroup,
		Rule:  []string{"ct state established,related counter accept"},
	})

	iccVerdict := "accept"
	if !n.config.ICC {
		iccVerdict = "drop"
	}

	if n.config.Internal {
		// Drop anything that's not from this network.
		tm.Create(nftables.RuleDesc{
			Chain: fwdInChain,
			Group: initialRuleGroup,
			Rule:  []string{`iifname != `, n.config.IfName, `counter drop comment "INTERNAL NETWORK INGRESS"`},
		})
		tm.Create(nftables.RuleDesc{
			Chain: fwdOutChain,
			Group: initialRuleGroup,
			Rule:  []string{`oifname != `, n.config.IfName, `counter drop comment "INTERNAL NETWORK EGRESS"`},
		})

		// Accept or drop Inter-Container Communication.
		tm.Create(nftables.RuleDesc{
			Chain: fwdInChain,
			Group: fwdInICCRuleGroup,
			Rule:  []string{"counter", iccVerdict, "comment ICC"},
		})
	} else {
		// Inter-Container Communication
		tm.Create(nftables.RuleDesc{
			Chain: fwdInChain,
			Group: fwdInICCRuleGroup,
			Rule:  []string{"iifname ==", n.config.IfName, "counter", iccVerdict, "comment ICC"},
		})

		// Outgoing traffic
		tm.Create(nftables.RuleDesc{
			Chain: fwdOutChain,
			Group: initialRuleGroup,
			Rule:  []string{"counter accept comment OUTGOING"},
		})

		// Incoming traffic
		if conf.Unprotected {
			tm.Create(nftables.RuleDesc{
				Chain: fwdInChain,
				Group: fwdInFinalRuleGroup,
				Rule:  []string{`counter accept comment "UNPROTECTED"`},
			})
		} else {
			tm.Create(nftables.RuleDesc{
				Chain: fwdInChain,
				Group: fwdInFinalRuleGroup,
				Rule:  []string{`counter drop comment "UNPUBLISHED PORT DROP"`},
			})
		}

		// ICMP
		if conf.Routed {
			rule := "ip protocol icmp"
			if tm.Family() == nftables.IPv6 {
				rule = "meta l4proto ipv6-icmp"
			}
			tm.Create(nftables.RuleDesc{
				Chain: fwdInChain,
				Group: initialRuleGroup,
				Rule:  []string{rule, "counter accept comment ICMP"},
			})
		}

		// Masquerade / SNAT - masquerade picks a source IP address based on next-hop, SNAT uses conf.HostIP.
		natPostroutingVerdict := "masquerade"
		natPostroutingComment := "MASQUERADE"
		if conf.HostIP.IsValid() {
			natPostroutingVerdict = "snat to " + conf.HostIP.Unmap().String()
			natPostroutingComment = "SNAT"
		}
		if n.config.Masquerade && !conf.Routed {
			tm.Create(nftables.RuleDesc{
				Chain: natPostRtOutChain,
				Group: initialRuleGroup,
				Rule: []string{
					"oifname !=", n.config.IfName, string(tm.Family()), "saddr", conf.Prefix.String(), "counter",
					natPostroutingVerdict, "comment", natPostroutingComment,
				},
			})
		}
		if n.fw.config.Hairpin {
			tm.Create(nftables.RuleDesc{
				Chain: natPostRtInChain,
				Group: initialRuleGroup,
				Rule: []string{
					`fib saddr type local counter`, natPostroutingVerdict, `comment "` + natPostroutingComment + ` FROM HOST"`,
				},
			})
		}
	}

	ctx = log.WithLogger(ctx, log.G(ctx).WithFields(log.Fields{
		"bridge": n.config.IfName,
		"family": tm.Family(),
	}))
	if err := tm.Apply(ctx); err != nil {
		return nftables.TableModifier{}, fmt.Errorf("adding rules for bridge %s: %w", n.config.IfName, err)
	}
	return tm.Reverse(), nil
}

func (n *network) ReapplyNetworkLevelRules(ctx context.Context) error {
	// A firewalld reload doesn't delete nftables rules, this function is not needed.
	log.G(ctx).Warn("ReapplyNetworkLevelRules is not implemented for nftables")
	return nil
}

func (n *network) DelNetworkLevelRules(ctx context.Context) error {
	remove := func(remover nftables.TableModifier) {
		if remover.IsValid() {
			ctx = log.WithLogger(ctx, log.G(ctx).WithFields(log.Fields{"bridge": n.config.IfName}))
			if err := remover.Apply(ctx); err != nil {
				log.G(ctx).WithError(err).Warn("Failed to remove network rules for network")
			}
		}
	}
	remove(n.remover4)
	n.remover4 = nftables.TableModifier{}
	remove(n.remover6)
	n.remover6 = nftables.TableModifier{}
	return nil
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
