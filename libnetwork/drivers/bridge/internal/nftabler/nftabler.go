package nftabler

import (
	"context"
	"fmt"

	"github.com/docker/docker/libnetwork/drivers/bridge/internal/firewaller"
	"github.com/docker/docker/libnetwork/internal/nftables"
)

const (
	dockerTable           = "docker-bridges"
	forwardChain          = "filter-FORWARD"
	postroutingChain      = "nat-POSTROUTING"
	preroutingChain       = "nat-PREROUTING"
	outputChain           = "nat-OUTPUT"
	natChain              = "nat-prerouting-and-output"
	rawPreroutingChain    = "raw-PREROUTING"
	filtFwdInVMap         = "filter-forward-in-jumps"
	filtFwdOutVMap        = "filter-forward-out-jumps"
	natPostroutingOutVMap = "nat-postrouting-out-jumps"
	natPostroutingInVMap  = "nat-postrouting-in-jumps"
	networkPrefixSet      = "network-prefix-set"

	// Priority 0 may be used by an iptables-nft created filter-FORWARD chain that has a
	// jump to a (legacy) DOCKER-USER chain. So, use priority 1 here.
	priFilterFwd = nftables.BaseChainPriorityFilter + 1
)

const (
	initialRuleGroup nftables.RuleGroup = iota
)

const (
	fwdInPortsRuleGroup = iota + initialRuleGroup + 1
	fwdInFinalRuleGroup
)

const (
	rawPreroutingPortsRuleGroup = iota + initialRuleGroup + 1
)

type nftabler struct {
	firewaller.Config
	table4 nftables.TableRef
	table6 nftables.TableRef
}

func NewNftabler(config firewaller.Config) (firewaller.Firewaller, error) {
	nft := &nftabler{Config: config}

	if nft.IPv4 {
		var err error
		nft.table4, err = nft.init(nftables.IPv4)
		if err != nil {
			return nil, err
		}
		if err := nftApply(context.Background(), nft.table4); err != nil {
			return nil, fmt.Errorf("IPv4 initialisation: %w", err)
		}
	}

	if nft.IPv6 {
		var err error
		nft.table6, err = nft.init(nftables.IPv6)
		if err != nil {
			return nil, err
		}

		// TODO(robmry) - on a host with IPv6 disabled, does startup need to continue on error (as for iptables)?
		if err := nftApply(context.Background(), nft.table6); err != nil {
			return nil, fmt.Errorf("IPv6 initialisation: %w", err)
		}
	}

	return nft, nil
}

func (nft *nftabler) getTable(ipv firewaller.IPVersion) nftables.TableRef {
	if ipv == firewaller.IPv4 {
		return nft.table4
	}
	return nft.table6
}

func (nft *nftabler) NewNetwork(nc firewaller.NetworkConfig) (firewaller.Network, error) {
	return newNetwork(nft, nc)
}

func (nft *nftabler) FilterForwardDrop(ipv firewaller.IPVersion) error {
	table := nft.getTable(ipv)
	if err := table.Chain(forwardChain).SetPolicy("drop"); err != nil {
		return err
	}
	return nftApply(context.Background(), table)
}

func (nft *nftabler) init(family nftables.Family) (nftables.TableRef, error) {
	// Filter table
	table, err := nftables.NewTable(family, dockerTable)
	if err != nil {
		return table, err
	}
	fwdChain, err := table.BaseChain(forwardChain, nftables.BaseChainTypeFilter, nftables.BaseChainHookForward, priFilterFwd)
	if err != nil {
		return nftables.TableRef{}, fmt.Errorf("initialising nftables: %w", err)
	}
	_ = table.InterfaceVMap(filtFwdInVMap)
	_ = table.InterfaceVMap(filtFwdOutVMap)
	_ = table.PrefixSet(networkPrefixSet)
	if err := fwdChain.AppendRule(initialRuleGroup, "oifname vmap @"+filtFwdInVMap); err != nil {
		return nftables.TableRef{}, fmt.Errorf("initialising nftables: %w", err)
	}
	if err := fwdChain.AppendRule(initialRuleGroup, "iifname vmap @"+filtFwdOutVMap); err != nil {
		return nftables.TableRef{}, fmt.Errorf("initialising nftables: %w", err)
	}

	// NAT postrouting
	natPostRtChain, err := table.BaseChain(postroutingChain,
		nftables.BaseChainTypeNAT,
		nftables.BaseChainHookPostrouting,
		nftables.BaseChainPrioritySrcNAT)
	if err != nil {
		return nftables.TableRef{}, err
	}
	_ = table.InterfaceVMap(natPostroutingOutVMap)
	if err := natPostRtChain.AppendRule(initialRuleGroup, "iifname vmap @"+natPostroutingOutVMap); err != nil {
		return nftables.TableRef{}, fmt.Errorf("initialising nftables: %w", err)
	}
	_ = table.InterfaceVMap(natPostroutingInVMap)
	if err := natPostRtChain.AppendRule(initialRuleGroup, "oifname vmap @"+natPostroutingInVMap); err != nil {
		return nftables.TableRef{}, fmt.Errorf("initialising nftables: %w", err)
	}
	// NAT prerouting
	_ = table.Chain(natChain)
	natPreRtChain, err := table.BaseChain(preroutingChain,
		nftables.BaseChainTypeNAT,
		nftables.BaseChainHookPrerouting,
		nftables.BaseChainPriorityDstNAT)
	if err != nil {
		return nftables.TableRef{}, err
	}
	if err := natPreRtChain.AppendRule(initialRuleGroup, "fib daddr type local counter jump "+natChain); err != nil {
		return nftables.TableRef{}, fmt.Errorf("initialising nftables: %w", err)
	}
	// NAT output
	_ = table.Chain(natChain)
	natOutputChain, err := table.BaseChain(outputChain,
		nftables.BaseChainTypeNAT,
		nftables.BaseChainHookOutput,
		nftables.BaseChainPriorityDstNAT)
	if err != nil {
		return nftables.TableRef{}, err
	}
	var skipLoopBack string
	if !nft.Hairpin {
		if family == nftables.IPv4 {
			skipLoopBack = "ip daddr != 127.0.0.1/8 "
		} else {
			skipLoopBack = "ip6 daddr != ::1 "
		}
	}
	if err := natOutputChain.AppendRule(initialRuleGroup, "%sfib daddr type local counter jump "+natChain, skipLoopBack); err != nil {
		return nftables.TableRef{}, fmt.Errorf("initialising nftables: %w", err)
	}

	// Raw prerouting
	if _, err := table.BaseChain(rawPreroutingChain,
		nftables.BaseChainTypeFilter,
		nftables.BaseChainHookPrerouting,
		nftables.BaseChainPriorityRaw); err != nil {
		return nftables.TableRef{}, err
	}
	return table, nil
}

func nftApply(ctx context.Context, table nftables.TableRef) error {
	if err := table.Apply(ctx); err != nil {
		return fmt.Errorf("applying nftables rules: %w", err)
	}
	return nil
}
