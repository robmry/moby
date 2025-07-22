//go:build linux

package nftabler

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"github.com/containerd/log"
	"github.com/docker/docker/daemon/libnetwork/drivers/bridge/internal/firewaller"
	"github.com/docker/docker/daemon/libnetwork/internal/nftables"
)

// Prefix for OTEL span names.
const spanPrefix = "libnetwork.drivers.bridge.nftabler"

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
)

const (
	initialRuleGroup nftables.RuleGroup = iota
)

const (
	fwdInLegacyLinksRuleGroup = iota + initialRuleGroup + 1
	fwdInICCRuleGroup
	fwdInPortsRuleGroup
	fwdInFinalRuleGroup
)

const (
	rawPreroutingPortsRuleGroup = iota + initialRuleGroup + 1
)

var baseChainNames = map[string]struct{}{
	forwardChain:       {},
	postroutingChain:   {},
	preroutingChain:    {},
	outputChain:        {},
	rawPreroutingChain: {},
}

type nftabler struct {
	config  firewaller.Config
	cleaner firewaller.FirewallCleaner
	table4  nftables.Table
	table6  nftables.Table
}

func NewNftabler(ctx context.Context, config firewaller.Config, baseChainPriorities map[string]string) (firewaller.Firewaller, error) {
	nft := &nftabler{config: config}

	// Convert base chain priorities to integers, assuming the daemon has called
	// ValidateBaseChainPriorities, so errors don't need to be handled.
	bcps := map[string]int{}
	for chain, prio := range baseChainPriorities {
		if p, err := strconv.Atoi(prio); err == nil {
			bcps[chain] = p
		}
	}

	if nft.config.IPv4 {
		var err error
		nft.table4, err = nft.init(ctx, nftables.IPv4, bcps)
		if err != nil {
			return nil, err
		}
	}

	if nft.config.IPv6 {
		var err error
		nft.table6, err = nft.init(ctx, nftables.IPv6, bcps)
		if err != nil {
			return nil, err
		}
	}

	return nft, nil
}

// ValidateBaseChainPriorities checks nftables base chain priority configuration.
func ValidateBaseChainPriorities(prios map[string]string) error {
	var errs []error
	for c, p := range prios {
		if _, ok := baseChainNames[c]; !ok {
			errs = append(errs, fmt.Errorf("%q is not a valid base chain name", c))
		}
		if _, ok := strconv.Atoi(p); ok != nil {
			errs = append(errs, fmt.Errorf("priority %q for base chain %q is not an integer", p, c))
		}
	}
	return errors.Join(errs...)
}

func (nft *nftabler) Reload(ctx context.Context) error {
	var errs []error
	if nft.config.IPv4 {
		errs = append(errs, nft.table4.Reload(ctx))
	}
	if nft.config.IPv6 {
		errs = append(errs, nft.table6.Reload(ctx))
	}
	return errors.Join(errs...)
}

func (nft *nftabler) getTable(ipv firewaller.IPVersion) nftables.Table {
	if ipv == firewaller.IPv4 {
		return nft.table4
	}
	return nft.table6
}

func (nft *nftabler) FilterForwardDrop(ctx context.Context, ipv firewaller.IPVersion) error {
	if err := nft.getTable(ipv).SetBaseChainPolicy(ctx, forwardChain, nftables.BaseChainPolicyDrop); err != nil {
		return fmt.Errorf("setting IPv%d filter-forward drop: %w", ipv, err)
	}
	return nil
}

// init creates the bridge driver's nftables table for IPv4 or IPv6.
func (nft *nftabler) init(ctx context.Context, family nftables.Family, baseChainPriorities map[string]int) (nftables.Table, error) {
	// Instantiate the table.
	table, err := nftables.NewTable(family, dockerTable)
	if err != nil {
		return table, err
	}

	// Reload the table while it's got no elements to clear an old table if one
	// exists. This is necessary because, if base chain priorities have changed and
	// the old table isn't removed, nft produces an error message for the base chain
	// (but seems to apply the change anyway).
	if err := table.Reload(ctx); err != nil {
		return nftables.Table{}, err
	}

	tm := table.Modifier()

	// Set up the filter forward chain.
	//
	// This base chain only contains two rules that use verdict maps:
	// - if a packet is entering a bridge network, jump to that network's filter-forward ingress chain.
	// - if a packet is leaving a bridge network, jump to that network's filter-forward egress chain.
	//
	// So, packets that aren't related to docker don't need to traverse any per-network filter forward
	// rules - and packets that are entering or leaving docker networks only need to traverse rules
	// related to those networks.
	tm.Create(nftables.BaseChain{
		Name:      forwardChain,
		ChainType: nftables.BaseChainTypeFilter,
		Hook:      nftables.BaseChainHookForward,
		Priority:  baseChainPriority(forwardChain, nftables.BaseChainPriorityFilter, baseChainPriorities),
	})
	// Instantiate the verdict maps and add the jumps.
	tm.Create(nftables.VMap{
		Name:        filtFwdInVMap,
		ElementType: nftables.NftTypeIfname,
	})
	tm.Create(nftables.Rule{
		Chain: forwardChain,
		Group: initialRuleGroup,
		Rule:  []string{"oifname vmap @", filtFwdInVMap},
	})

	tm.Create(nftables.VMap{
		Name:        filtFwdOutVMap,
		ElementType: nftables.NftTypeIfname,
	})
	tm.Create(nftables.Rule{
		Chain: forwardChain,
		Group: initialRuleGroup,
		Rule:  []string{"iifname vmap @", filtFwdOutVMap},
	})

	// Set up the NAT postrouting base chain.
	//
	// Like the filter-forward chain, its only rules are jumps to network-specific ingress and egress chains.
	tm.Create(nftables.BaseChain{
		Name:      postroutingChain,
		ChainType: nftables.BaseChainTypeNAT,
		Hook:      nftables.BaseChainHookPostrouting,
		Priority:  baseChainPriority(postroutingChain, nftables.BaseChainPrioritySrcNAT, baseChainPriorities),
	})

	tm.Create(nftables.VMap{
		Name:        natPostroutingOutVMap,
		ElementType: nftables.NftTypeIfname,
	})
	tm.Create(nftables.Rule{
		Chain: postroutingChain,
		Group: initialRuleGroup,
		Rule:  []string{"iifname vmap @", natPostroutingOutVMap},
	})

	tm.Create(nftables.VMap{
		Name:        natPostroutingInVMap,
		ElementType: nftables.NftTypeIfname,
	})
	tm.Create(nftables.Rule{
		Chain: postroutingChain,
		Group: initialRuleGroup,
		Rule:  []string{"oifname vmap @", natPostroutingInVMap},
	})

	// Instantiate natChain, for the NAT prerouting and output base chains to jump to.
	tm.Create(nftables.Chain{
		Name: natChain,
	})

	// Set up the NAT prerouting base chain.
	tm.Create(nftables.BaseChain{
		Name:      preroutingChain,
		ChainType: nftables.BaseChainTypeNAT,
		Hook:      nftables.BaseChainHookPrerouting,
		Priority:  baseChainPriority(preroutingChain, nftables.BaseChainPriorityDstNAT, baseChainPriorities),
	})
	tm.Create(nftables.Rule{
		Chain: preroutingChain,
		Group: initialRuleGroup,
		Rule:  []string{"fib daddr type local counter jump", natChain},
	})

	// Set up the NAT output base chain
	tm.Create(nftables.BaseChain{
		Name:      outputChain,
		ChainType: nftables.BaseChainTypeNAT,
		Hook:      nftables.BaseChainHookOutput,
		Priority:  baseChainPriority(outputChain, nftables.BaseChainPriorityDstNAT, baseChainPriorities),
	})

	// For output, don't jump to the NAT chain if hairpin is enabled (no userland proxy).
	var skipLoopback string
	if !nft.config.Hairpin {
		if family == nftables.IPv4 {
			skipLoopback = "ip daddr != 127.0.0.1/8 "
		} else {
			skipLoopback = "ip6 daddr != ::1 "
		}
	}
	tm.Create(nftables.Rule{
		Chain: outputChain,
		Group: initialRuleGroup,
		Rule:  []string{skipLoopback, "fib daddr type local counter jump", natChain},
	})

	// Set up the raw prerouting base chain
	tm.Create(nftables.BaseChain{
		Name:      rawPreroutingChain,
		ChainType: nftables.BaseChainTypeFilter,
		Hook:      nftables.BaseChainHookPrerouting,
		Priority:  baseChainPriority(rawPreroutingChain, nftables.BaseChainPriorityRaw, baseChainPriorities),
	})

	if !nft.config.Hairpin && nft.config.WSL2Mirrored {
		mirroredWSL2Workaround(tm)
	}

	if err := tm.Apply(ctx); err != nil {
		if family == nftables.IPv4 {
			return nftables.Table{}, err
		}
		// Perhaps the kernel has no IPv6 support. It won't be possible to create IPv6
		// networks without enabling ip6_tables in the kernel, or disabling ip6tables in
		// the daemon config. But, allow the daemon to start because IPv4 will work. So,
		// log the problem, and continue.
		log.G(ctx).WithError(err).Warn("ip6tables is enabled, but cannot set up IPv6 nftables table")
		return nftables.Table{}, nil
	}
	return table, nil
}

func baseChainPriority(chainName string, def int, overrides map[string]int) int {
	if p, ok := overrides[chainName]; ok {
		return p
	}
	return def
}
