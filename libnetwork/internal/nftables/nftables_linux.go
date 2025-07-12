// FIXME(thaJeztah): remove once we are a module; the go:build directive prevents go from downgrading language version to go1.16:
//go:build go1.23

// Package nftables provides methods to create an nftables table and manage its maps, sets,
// chains, and rules.
//
// To use it, the first step is to create a [Table] using [NewTable]. The table can
// then be populated and managed using that ref.
//
// Modifications to the table are only applied (sent to "nft") when [Table.Apply] is
// called. This means a number of updates can be made, for example, adding all the
// rules needed for a docker network - and those rules will then be applied atomically
// in a single "nft" run.
//
// [Table.Apply] can only be called after [Enable], and only if [Enable] returns
// true (meaning an "nft" executable was found). [Enabled] can be called to check
// whether nftables has been enabled.
//
// Be aware:
//   - The implementation is far from complete, only functionality needed so-far has
//     been included. Currently, there's only a limited set of chain/map/set types,
//     there's no way to delete sets/maps etc.
//   - There's no rollback so, once changes have been made to a Table, if the
//     Apply fails there is no way to undo changes. The Table will be out-of-sync
//     with the actual state of nftables.
//   - This is a thin layer between code and "nft", it doesn't do much error checking. So,
//     for example, if you get the syntax of a rule wrong the issue won't be reported
//     until Apply is called.
//   - Also in the category of no-error-checking, there's no reference checking. If you
//     delete a chain that's still referred to by a map, set or another chain, "nft" will
//     report an error when Apply is called.
//   - Error checking here is meant to help spot logical errors in the code, like adding
//     a rule twice, which would be fine by "nft" as it'd just create a duplicate rule.
//   - The existing state of a table in the ruleset is irrelevant, once a Table is created
//     by this package it will be flushed. Putting it another way, this package is
//     write-only, it does not load any state from the host.
//   - Errors from "nft" are logged along with the line-numbered command that failed,
//     that's the place to look when things go wrong.
package nftables

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"sync"
	"text/template"

	"github.com/containerd/log"
	"go.opentelemetry.io/otel"
)

// Prefix for OTEL span names.
const spanPrefix = "libnetwork.internal.nftables"

var (
	// nftPath is the path of the "nft" tool, set by [Enable] and left empty if the tool
	// is not present - in which case, nftables is disabled.
	nftPath string
	// Error returned by Enable if nftables could not be initialised.
	nftEnableError error
	// incrementalUpdateTempl is a parsed text/template, used to apply incremental updates.
	incrementalUpdateTempl *template.Template
	// reloadTempl is a parsed text/template, used to apply a whole table.
	reloadTempl *template.Template
	// enableOnce is used by [Enable] to avoid checking the path for "nft" more than once.
	enableOnce sync.Once
)

// BaseChainType enumerates the base chain types.
// See https://wiki.nftables.org/wiki-nftables/index.php/Configuring_chains#Base_chain_types
type BaseChainType string

const (
	BaseChainTypeFilter BaseChainType = "filter"
	BaseChainTypeRoute  BaseChainType = "route"
	BaseChainTypeNAT    BaseChainType = "nat"
)

// BaseChainHook enumerates the base chain hook types.
// See https://wiki.nftables.org/wiki-nftables/index.php/Configuring_chains#Base_chain_hooks
type BaseChainHook string

const (
	BaseChainHookIngress     BaseChainHook = "ingress"
	BaseChainHookPrerouting  BaseChainHook = "prerouting"
	BaseChainHookInput       BaseChainHook = "input"
	BaseChainHookForward     BaseChainHook = "forward"
	BaseChainHookOutput      BaseChainHook = "output"
	BaseChainHookPostrouting BaseChainHook = "postrouting"
)

// Standard priority values for base chains.
// (Not for the bridge family, those are different.)
const (
	BaseChainPriorityRaw      = -300
	BaseChainPriorityMangle   = -150
	BaseChainPriorityDstNAT   = -100
	BaseChainPriorityFilter   = 0
	BaseChainPrioritySecurity = 50
	BaseChainPrioritySrcNAT   = 100
)

// Family enumerates address families.
type Family string

const (
	IPv4 Family = "ip"
	IPv6 Family = "ip6"
)

// NftType enumerates nft types that can be used to define maps/sets etc.
type NftType string

const (
	NftTypeIPv4Addr    NftType = "ipv4_addr"
	NftTypeIPv6Addr    NftType = "ipv6_addr"
	NftTypeEtherAddr   NftType = "ether_addr"
	NftTypeInetProto   NftType = "inet_proto"
	NftTypeInetService NftType = "inet_service"
	NftTypeMark        NftType = "mark"
	NftTypeIfname      NftType = "ifname"
)

// Enable tries once to initialise nftables.
func Enable() error {
	enableOnce.Do(func() {
		path, err := exec.LookPath("nft")
		if err != nil {
			log.G(context.Background()).WithError(err).Warnf("Failed to find nft tool")
			nftEnableError = fmt.Errorf("failed to find nft tool: %w", err)
			return
		}
		if err := parseTemplate(); err != nil {
			log.G(context.Background()).WithError(err).Error("Internal error while initialising nftables")
			nftEnableError = fmt.Errorf("internal error while initialising nftables: %w", err)
			return
		}
		nftPath = path
	})
	return nftEnableError
}

// Enabled returns true if the "nft" tool is available and [Enable] has been called.
func Enabled() bool {
	return nftPath != ""
}

// Disable undoes Enable. Intended for unit testing.
func Disable() {
	nftPath = ""
	incrementalUpdateTempl = nil
	reloadTempl = nil
	enableOnce = sync.Once{}
}

//////////////////////////////
// Tables

// Table is a handle for an nftables table.
type Table struct {
	t *table
}

func (t *Table) IsValid() bool {
	return t.t != nil
}

// NewTable creates a new nftables table and returns a [Table]
//
// See https://wiki.nftables.org/wiki-nftables/index.php/Configuring_tables
//
// The table will be created and flushed when [Table.Apply] is next called.
// It's flushed in case it already exists in the host's nftables - when that
// happens, rules in its chains will be deleted but not the chains themselves,
// maps, sets, or elements of maps or sets. But, those un-flushed items can't do
// anything disruptive unless referred to by rules, and they will be flushed if
// they get re-created via the [Table], when [Table.Apply] is next called
// (so, before they can be used by a new rule).
func NewTable(family Family, name string) (Table, error) {
	t := Table{
		t: &table{
			Name:      name,
			Family:    family,
			VMaps:     map[string]*vMap{},
			Sets:      map[string]*set{},
			Chains:    map[string]*chain{},
			MustFlush: true,
		},
	}
	return t, nil
}

func (t Table) Name() string {
	return t.t.Name
}

func (t Table) Modifier() TableModifier {
	return TableModifier{t: t.t}
}

// SetPolicy sets the default policy for a base chain. It is an error to call this
// for a non-base [ChainRef].
func (t Table) SetBaseChainPolicy(ctx context.Context, chainName, policy string) error {
	if !t.IsValid() {
		return errors.New("invalid table")
	}
	c := t.t.Chains[chainName]
	if c == nil {
		return fmt.Errorf("cannot set base chain policy for '%s', it does not exist", chainName)
	}
	if c.ChainType == "" {
		return fmt.Errorf("cannot set base chain policy for '%s', it is not a base chain", chainName)
	}
	oldPolicy := c.Policy
	c.Policy = policy
	c.MustFlush = true

	if err := t.Modifier().Apply(ctx); err != nil {
		c.Policy = oldPolicy
		return err
	}
	return nil
}

type Command interface {
	create(context.Context, *table) error
	delete(context.Context, *table) error
}

type TableModifier struct {
	t    *table
	cmds []cmdEntry
}

func (tm *TableModifier) IsValid() bool {
	return tm.t != nil
}

func (tm *TableModifier) Name() string {
	return tm.t.Name
}

// Family returns the address family of the nftables table described by [Table].
func (tm *TableModifier) Family() Family {
	return tm.t.Family
}

func (tm *TableModifier) Create(cmd Command) {
	tm.cmds = append(tm.cmds, cmdEntry{c: cmd})
}

func (tm *TableModifier) Delete(cmd Command) {
	tm.cmds = append(tm.cmds, cmdEntry{c: cmd, reverse: true})
}

func (tm *TableModifier) Reverse() TableModifier {
	rtm := TableModifier{
		t:    tm.t,
		cmds: make([]cmdEntry, len(tm.cmds)),
	}
	for i, cmd := range tm.cmds {
		cmd.reverse = !cmd.reverse
		rtm.cmds[len(tm.cmds)-i-1] = cmd
	}
	return rtm
}

// Apply makes incremental updates to nftables, corresponding to changes to the [Table]
// since Apply was last called.
func (tm TableModifier) Apply(ctx context.Context) (retErr error) {
	if !Enabled() {
		return errors.New("nftables is not enabled")
	}

	var cmdsProcessed int
	defer func() {
		if retErr == nil {
			return
		}
		for cmdsProcessed > 0 {
			cmdsProcessed--
			c := tm.cmds[cmdsProcessed]
			if c.reverse {
				if err := c.c.create(ctx, tm.t); err != nil {
					log.G(ctx).WithError(err).Error("Failed to roll back nftables updates")
				}
			} else {
				if err := c.c.delete(ctx, tm.t); err != nil {
					log.G(ctx).WithError(err).Error("Failed to roll back nftables updates")
				}
			}
		}
		tm.t.updatesApplied()
	}()

	for _, cmd := range tm.cmds {
		if cmd.reverse {
			if err := cmd.c.delete(ctx, tm.t); err != nil {
				return err
			}
		} else {
			if err := cmd.c.create(ctx, tm.t); err != nil {
				return err
			}
		}
		cmdsProcessed++
	}

	// Update nftables.
	var buf bytes.Buffer
	if err := incrementalUpdateTempl.Execute(&buf, tm.t); err != nil {
		return fmt.Errorf("failed to execute template nft ruleset: %w", err)
	}

	if err := nftApply(ctx, buf.Bytes()); err != nil {
		// On error, log a line-numbered version of the generated "nft" input (because
		// nft error messages refer to line numbers).
		var sb strings.Builder
		for i, line := range bytes.SplitAfter(buf.Bytes(), []byte("\n")) {
			sb.WriteString(strconv.Itoa(i + 1))
			sb.WriteString(":\t")
			sb.Write(line)
		}
		log.G(ctx).Error("nftables: failed to update nftables:\n", sb.String(), "\n", err)

		// It's possible something destructive has happened to nftables. For example, in
		// integration-cli tests, tests start daemons in the same netns as the integration
		// test's own daemon. They don't always use their own daemon, but they tend to leave
		// behind networks for the test infrastructure to clean up between tests. Starting
		// a daemon flushes the "docker-bridges" table, so the cleanup fails to delete a
		// rule that's been flushed. So, try reloading the whole table to get back in-sync.
		return tm.t.reload(ctx)
	}

	// Note that updates have been applied.
	tm.t.updatesApplied()
	return nil
}

// Reload deletes the table, then re-creates it, atomically.
func (t Table) Reload(ctx context.Context) error {
	return t.t.reload(ctx)
}

func (t *table) reload(ctx context.Context) error {
	if !Enabled() {
		return errors.New("nftables is not enabled")
	}

	ctx = log.WithLogger(ctx, log.G(ctx).WithFields(log.Fields{"table": t.Name, "family": t.Family}))
	log.G(ctx).Warn("nftables: reloading table")

	// Build the update.
	var buf bytes.Buffer
	if err := reloadTempl.Execute(&buf, t); err != nil {
		return fmt.Errorf("failed to execute reload template: %w", err)
	}

	if err := nftApply(ctx, buf.Bytes()); err != nil {
		// On error, log a line-numbered version of the generated "nft" input (because
		// nft error messages refer to line numbers).
		var sb strings.Builder
		for i, line := range bytes.SplitAfter(buf.Bytes(), []byte("\n")) {
			sb.WriteString(strconv.Itoa(i + 1))
			sb.WriteString(":\t")
			sb.Write(line)
		}
		log.G(ctx).Error("nftables: failed to reload nftable:\n", sb.String(), "\n", err)
		return err
	}

	// Note that updates have been applied.
	t.updatesApplied()
	return nil
}

// ////////////////////////////
// Chains

// BaseChain constructs a new nftables base chain and returns a [ChainRef].
//
// See https://wiki.nftables.org/wiki-nftables/index.php/Configuring_chains#Adding_base_chains
//
// It is an error to create a base chain that already exists.
// If the underlying chain already exists, it will be flushed by the
// next [Table.Apply] before new rules are added.
type BaseChainDesc struct {
	Name      string
	ChainType BaseChainType
	Hook      BaseChainHook
	Priority  int
	Policy    string
}

func (cd BaseChainDesc) create(ctx context.Context, t *table) error {
	if _, ok := t.Chains[cd.Name]; ok {
		return fmt.Errorf("base chain %q already exists", cd.Name)
	}
	c := &chain{
		table:      t,
		Name:       cd.Name,
		ChainType:  cd.ChainType,
		Hook:       cd.Hook,
		Priority:   cd.Priority,
		Policy:     cd.Policy,
		MustFlush:  true,
		ruleGroups: map[RuleGroup][]string{},
	}
	t.Chains[c.Name] = c
	log.G(ctx).WithFields(log.Fields{
		"family": t.Family,
		"table":  t.Name,
		"chain":  c.Name,
		"type":   c.ChainType,
		"hook":   c.Hook,
		"prio":   c.Priority,
	}).Debug("nftables: created base chain")
	return nil
}

func (cd BaseChainDesc) delete(ctx context.Context, t *table) error {
	return t.deleteChain(ctx, cd.Name)
}

type ChainDesc struct {
	Name string
}

func (cd ChainDesc) create(ctx context.Context, t *table) error {
	if _, ok := t.Chains[cd.Name]; ok {
		return fmt.Errorf("chain %q already exists", cd.Name)
	}
	c := &chain{
		table:      t,
		Name:       cd.Name,
		MustFlush:  true,
		ruleGroups: map[RuleGroup][]string{},
	}
	t.Chains[c.Name] = c
	log.G(ctx).WithFields(log.Fields{
		"family": t.Family,
		"table":  t.Name,
		"chain":  cd.Name,
	}).Debug("nftables: created chain")
	return nil
}

func (cd ChainDesc) delete(ctx context.Context, t *table) error {
	return t.deleteChain(ctx, cd.Name)
}

// RuleGroup is used to allocate rules within a chain to a group. These groups are
// purely an internal construct, nftables knows nothing about them. Within groups
// rules retain the order in which they were added, and groups are ordered from
// lowest to highest numbered group.
type RuleGroup int

type RuleDesc struct {
	Chain       string
	Group       RuleGroup
	Rule        []string
	IgnoreExist bool
}

func (rd RuleDesc) create(ctx context.Context, t *table) error {
	c := t.Chains[rd.Chain]
	if c == nil {
		return fmt.Errorf("chain %q does not exist", rd.Chain)
	}
	rule := strings.Join(rd.Rule, " ")
	if !rd.IgnoreExist {
		if rg, ok := c.ruleGroups[rd.Group]; ok && slices.Contains(rg, rule) {
			return fmt.Errorf("addimng rule:'%s' chain:'%s' group:%d: rule exists", rule, rd.Chain, rd.Group)
		}
	}
	c.ruleGroups[rd.Group] = append(c.ruleGroups[rd.Group], rule)
	c.MustFlush = true
	log.G(ctx).WithFields(log.Fields{
		"family": t.Family,
		"table":  t.Name,
		"chain":  c.Name,
		"group":  rd.Group,
		"rule":   rule,
	}).Debug("nftables: appended rule")
	return nil
}

func (rd RuleDesc) delete(ctx context.Context, t *table) error {
	rule := strings.Join(rd.Rule, " ")
	c := t.Chains[rd.Chain]
	if c == nil {
		return fmt.Errorf("deleting rule:'%s' - chain '%s' does not exist", rule, rd.Chain)
	}
	rg, ok := c.ruleGroups[rd.Group]
	if !ok {
		return fmt.Errorf("deleting rule:'%s' chain:'%s' rule group:%d does not exist", rule, rd.Chain, rd.Group)
	}
	origLen := len(rg)
	c.ruleGroups[rd.Group] = slices.DeleteFunc(rg, func(r string) bool { return r == rule })
	if !rd.IgnoreExist && len(c.ruleGroups[rd.Group]) == origLen {
		return fmt.Errorf("deleting rule:'%s' chain:'%s' group:%d: rule does not exist", rule, rd.Chain, rd.Group)
	}
	if len(c.ruleGroups[rd.Group]) == 0 {
		delete(c.ruleGroups, rd.Group)
	}
	c.MustFlush = true
	log.G(ctx).WithFields(log.Fields{
		"family": t.Family,
		"table":  t.Name,
		"chain":  c.Name,
		"rule":   rule,
	}).Debug("nftables: deleted rule")
	return nil
}

// ////////////////////////////
// VMaps

// vMap is the internal representation of an nftables verdict map.
// Its elements need to be exported for use by text/template, but they should only be
// manipulated via exported methods.
type vMap struct {
	table           *table
	Name            string
	ElementType     NftType
	Flags           []string
	Elements        map[string]string
	AddedElements   map[string]string
	DeletedElements map[string]string
	MustFlush       bool
}

type VMapDesc struct {
	Name        string
	ElementType NftType
	Flags       []string
}

func (vd VMapDesc) create(ctx context.Context, t *table) error {
	if _, ok := t.VMaps[vd.Name]; ok {
		return fmt.Errorf("vmap %q already exists", vd.Name)
	}
	v := &vMap{
		table:           t,
		Name:            vd.Name,
		ElementType:     vd.ElementType,
		Flags:           slices.Clone(vd.Flags),
		Elements:        map[string]string{},
		AddedElements:   map[string]string{},
		DeletedElements: map[string]string{},
		MustFlush:       true,
	}
	t.VMaps[v.Name] = v
	log.G(ctx).WithFields(log.Fields{
		"family": t.Family,
		"table":  t.Name,
		"vmap":   v.Name,
	}).Debug("nftables: created interface vmap")
	return nil
}

// rollback only - the text-template can't delete old vmaps
func (vd VMapDesc) delete(ctx context.Context, t *table) error {
	v := t.VMaps[vd.Name]
	if v == nil {
		return fmt.Errorf("cannot delete vmap %q, it does not exist", vd.Name)
	}
	if len(v.Elements) != 0 {
		return fmt.Errorf("cannot delete vmap %q, it contains %d elements", v.Name, len(v.Elements))
	}
	delete(t.VMaps, v.Name)
	t.DeleteCommands = append(t.DeleteCommands,
		fmt.Sprintf("delete map %s %s %s", t.Family, t.Name, v.Name))
	log.G(ctx).WithFields(log.Fields{
		"family": t.Family,
		"table":  t.Name,
		"vmap":   v.Name,
	}).Debug("nftables: deleted vmap")
	return nil
}

type VMapElementDesc struct {
	Name    string
	Key     string
	Verdict string
}

func (vd VMapElementDesc) create(ctx context.Context, t *table) error {
	v := t.VMaps[vd.Name]
	if v == nil {
		return fmt.Errorf("cannot add to vmap %q, it does not exist", vd.Name)
	}
	if _, ok := v.Elements[vd.Key]; ok {
		return fmt.Errorf("verdict map %q already contains element %q", vd.Name, vd.Key)
	}
	v.Elements[vd.Key] = vd.Verdict
	v.AddedElements[vd.Key] = vd.Verdict
	delete(v.DeletedElements, vd.Key)
	log.G(ctx).WithFields(log.Fields{
		"family":  t.Family,
		"table":   t.Name,
		"vmap":    vd.Name,
		"key":     vd.Key,
		"verdict": vd.Verdict,
	}).Debug("nftables: added vmap element")
	return nil
}

func (vd VMapElementDesc) delete(ctx context.Context, t *table) error {
	v := t.VMaps[vd.Name]
	if v == nil {
		return fmt.Errorf("cannot delete from vmap %q, it does not exist", vd.Name)
	}
	oldVerdict, ok := v.Elements[vd.Key]
	if !ok {
		return fmt.Errorf("verdict map %q does not contain element %q", vd.Name, vd.Key)
	}
	if oldVerdict != vd.Verdict {
		return fmt.Errorf("cannot delete verdict map %q element %q, verdict was %q, not %q",
			vd.Name, vd.Key, oldVerdict, vd.Verdict)
	}
	delete(v.Elements, vd.Key)
	delete(v.AddedElements, vd.Key)
	v.DeletedElements[vd.Key] = vd.Verdict
	log.G(ctx).WithFields(log.Fields{
		"family":  t.Family,
		"table":   t.Name,
		"vmap":    vd.Name,
		"key":     vd.Key,
		"verdict": vd.Verdict,
	}).Debug("nftables: deleted vmap element")
	return nil
}

// ////////////////////////////
// Sets

// set is the internal representation of an nftables set.
// Its elements need to be exported for use by text/template, but they should only be
// manipulated via exported methods.
type set struct {
	table           *table
	Name            string
	ElementType     NftType
	Flags           []string
	Elements        map[string]struct{}
	AddedElements   map[string]struct{}
	DeletedElements map[string]struct{}
	MustFlush       bool
}

type PrefixSetDesc struct {
	Name string
}

// See https://wiki.nftables.org/wiki-nftables/index.php/Sets#Named_sets
func (pd PrefixSetDesc) create(ctx context.Context, t *table) error {
	if _, ok := t.Sets[pd.Name]; ok {
		return fmt.Errorf("set %q already exists", pd.Name)
	}
	et := NftTypeIPv4Addr
	if t.Family == IPv6 {
		et = NftTypeIPv6Addr
	}
	s := &set{
		table:           t,
		Name:            pd.Name,
		Elements:        map[string]struct{}{},
		ElementType:     et,
		Flags:           []string{"interval"},
		AddedElements:   map[string]struct{}{},
		DeletedElements: map[string]struct{}{},
		MustFlush:       true,
	}
	t.Sets[pd.Name] = s
	log.G(ctx).WithFields(log.Fields{
		"family": t.Family,
		"table":  t.Name,
		"set":    s.Name,
	}).Debug("nftables: created prefix set")
	return nil
}

func (pd PrefixSetDesc) delete(ctx context.Context, t *table) error {
	s := t.Sets[pd.Name]
	if s == nil {
		return fmt.Errorf("cannot delete prefix set %q, it does not exist", pd.Name)
	}
	if len(s.Elements) != 0 {
		return fmt.Errorf("cannot delete prefix set %q, it contains %d elements", s.Name, len(s.Elements))
	}
	delete(t.Sets, pd.Name)
	t.DeleteCommands = append(t.DeleteCommands,
		fmt.Sprintf("delete set %s %s %s", t.Family, t.Name, s.Name))
	log.G(ctx).WithFields(log.Fields{
		"family": t.Family,
		"table":  t.Name,
		"set":    pd.Name,
	}).Debug("nftables: deleted prefix set")
	return nil
}

type PrefixSetElementDesc struct {
	Name   string
	Prefix string
}

func (pd PrefixSetElementDesc) create(ctx context.Context, t *table) error {
	s := t.Sets[pd.Name]
	if s == nil {
		return fmt.Errorf("cannot add to prefix set %q, it does not exist", pd.Name)
	}
	if _, ok := s.Elements[pd.Prefix]; ok {
		return fmt.Errorf("set %q already contains prefix %q", s.Name, pd.Prefix)
	}
	s.Elements[pd.Prefix] = struct{}{}
	s.AddedElements[pd.Prefix] = struct{}{}
	delete(s.DeletedElements, pd.Prefix)
	log.G(ctx).WithFields(log.Fields{
		"family":  t.Family,
		"table":   t.Name,
		"set":     s.Name,
		"element": pd.Prefix,
	}).Debug("nftables: added prefix set element")
	return nil
}

func (pd PrefixSetElementDesc) delete(ctx context.Context, t *table) error {
	s := t.Sets[pd.Name]
	if s == nil {
		return fmt.Errorf("cannot delete from prefix set %q, it does not exist", pd.Name)
	}
	if _, ok := s.Elements[pd.Prefix]; !ok {
		return fmt.Errorf("cannot delete prefix %q from set %q, it does not exist", pd.Prefix, s.Name)
	}
	delete(s.Elements, pd.Prefix)
	s.DeletedElements[pd.Prefix] = struct{}{}
	delete(s.AddedElements, pd.Prefix)
	log.G(ctx).WithFields(log.Fields{
		"family":  t.Family,
		"table":   t.Name,
		"set":     s.Name,
		"element": pd.Prefix,
	}).Debug("nftables: added prefix set element")
	return nil
}

// ////////////////////////////
// Internal
// table is the internal representation of an nftables table.
// Its elements need to be exported for use by text/template, but they should only be
// manipulated via exported methods.

type table struct {
	Name   string
	Family Family

	VMaps  map[string]*vMap
	Sets   map[string]*set
	Chains map[string]*chain

	DeleteCommands []string
	MustFlush      bool
}

func (t *table) deleteChain(ctx context.Context, name string) error {
	c := t.Chains[name]
	if c == nil {
		return fmt.Errorf("cannot delete chain '%s', it does not exist", name)
	}
	if len(c.ruleGroups) != 0 {
		return fmt.Errorf("cannot delete chain '%s', it is not empty", name)
	}
	delete(t.Chains, name)
	t.DeleteCommands = append(t.DeleteCommands,
		fmt.Sprintf("delete chain %s %s %s", t.Family, t.Name, name))
	log.G(ctx).WithFields(log.Fields{
		"family": t.Family,
		"table":  t.Name,
		"chain":  name,
	}).Debug("nftables: deleted chain")
	return nil
}

type cmdEntry struct {
	c       Command
	reverse bool
}

// incrementalUpdateTemplText is used with text/template to generate an nftables command file
// (which will be applied atomically). Updates using this template are always incremental.
// Steps are:
//   - declare the table and its sets/maps with empty versions of modified chains, so that
//     they can be flushed/deleted if they don't yet exist. (They need to be flushed in case
//     a version of them was left behind by an old incarnation of the daemon. But, it's an
//     error to flush or delete something that doesn't exist. So, avoid having to parse nft's
//     stderr to work out what happened by making sure they do exist before flushing.)
//   - if the table is newly declared, flush rules from its chains
//   - flush each newly declared map/set
//   - delete deleted map/set elements
//   - flush modified chains
//   - delete deleted chains
//   - re-populate modified chains
//   - add new map/set elements
const incrementalUpdateTemplText = `{{$family := .Family}}{{$tableName := .Name}}
table {{$family}} {{$tableName}} {
	{{range .VMaps}}map {{.Name}} {
		type {{.ElementType}} : verdict
		{{if len .Flags}}flags{{range .Flags}} {{.}}{{end}}{{end}}
	}
	{{end}}
	{{range .Sets}}set {{.Name}} {
		type {{.ElementType}}
		{{if len .Flags}}flags{{range .Flags}} {{.}}{{end}}{{end}}
	}
	{{end}}
	{{range .Chains}}{{if .MustFlush}}chain {{.Name}} {
		{{if .ChainType}}type {{.ChainType}} hook {{.Hook}} priority {{.Priority}}; policy {{.Policy}}{{end}}
	} ; {{end}}{{end}}
}
{{if .MustFlush}}flush table {{$family}} {{$tableName}}{{end}}
{{range .VMaps}}{{if .MustFlush}}flush map {{$family}} {{$tableName}} {{.Name}}
{{end}}{{end}}
{{range .Sets}}{{if .MustFlush}}flush set {{$family}} {{$tableName}} {{.Name}}
{{end}}{{end}}
{{range .Chains}}{{if .MustFlush}}flush chain {{$family}} {{$tableName}} {{.Name}}
{{end}}{{end}}
{{range .VMaps}}{{if .DeletedElements}}delete element {{$family}} {{$tableName}} {{.Name}} { {{range $k,$v := .DeletedElements}}{{$k}}, {{end}} }
{{end}}{{end}}
{{range .Sets}}{{if .DeletedElements}}delete element {{$family}} {{$tableName}} {{.Name}} { {{range $k,$v := .DeletedElements}}{{$k}}, {{end}} }
{{end}}{{end}}
{{range .DeleteCommands}}{{.}}
{{end}}
table {{$family}} {{$tableName}} {
	{{range .Chains}}{{if .MustFlush}}chain {{.Name}} {
		{{if .ChainType}}type {{.ChainType}} hook {{.Hook}} priority {{.Priority}}; policy {{.Policy}}{{end}}
		{{range .Rules}}{{.}}
		{{end}}
	}
	{{end}}{{end}}
}
{{range .VMaps}}{{if .AddedElements}}add element {{$family}} {{$tableName}} {{.Name}} { {{range $k,$v := .AddedElements}}{{$k}} : {{$v}}, {{end}} }
{{end}}{{end}}
{{range .Sets}}{{if .AddedElements}}add element {{$family}} {{$tableName}} {{.Name}} { {{range $k,$v := .AddedElements}}{{$k}}, {{end}} }
{{end}}{{end}}
`

// reloadTemplText is used with text/template to generate an nftables command file
// (which will be applied atomically), to fully re-create a table.
//
// It first declares the table so if it doesn't already exist, it can be deleted.
// Then it deletes the table and re-creates it.
const reloadTemplText = `{{$family := .Family}}{{$tableName := .Name}}
table {{$family}} {{$tableName}} {}
delete table {{$family}} {{$tableName}}
table {{$family}} {{$tableName}} {
	{{range .VMaps}}map {{.Name}} {
		type {{.ElementType}} : verdict
		{{if len .Flags}}flags{{range .Flags}} {{.}}{{end}}{{end}}
        {{if .Elements}}elements = {
			{{range $k,$v := .Elements}}{{$k}} : {{$v}},
            {{end -}}
		}{{end}}
	}
	{{end}}
	{{range .Sets}}set {{.Name}} {
		type {{.ElementType}}
		{{if len .Flags}}flags{{range .Flags}} {{.}}{{end}}{{end}}
        {{if .Elements}}elements = {
			{{range $k,$v := .Elements}}{{$k}},
            {{end -}}
		}{{end}}
	}
	{{end}}
	{{range .Chains}}chain {{.Name}} {
		{{if .ChainType}}type {{.ChainType}} hook {{.Hook}} priority {{.Priority}}; policy {{.Policy}}{{end}}
		{{range .Rules}}{{.}}
		{{end}}
	}
	{{end}}
}
`

func (t *table) updatesApplied() {
	t.DeleteCommands = t.DeleteCommands[:0]
	for _, c := range t.Chains {
		c.MustFlush = false
	}
	for _, m := range t.VMaps {
		m.AddedElements = map[string]string{}
		m.DeletedElements = map[string]string{}
		m.MustFlush = false
	}
	for _, s := range t.Sets {
		s.AddedElements = map[string]struct{}{}
		s.DeletedElements = map[string]struct{}{}
		s.MustFlush = false
	}
	t.MustFlush = false
}

/* Can't make text/template range over this, not sure why ...
func (c *chain) Rules() iter.Seq[string] {
	groups := make([]int, 0, len(c.ruleGroups))
	for group := range c.ruleGroups {
		groups = append(groups, group)
	}
	slices.Sort(groups)
	return func(yield func(string) bool) {
		for _, group := range groups {
			for _, rule := range c.ruleGroups[group] {
				if !yield(rule) {
					return
				}
			}
		}
	}
}
*/

// chain is the internal representation of an nftables chain.
// Its elements need to be exported for use by text/template, but they should only be
// manipulated via exported methods.
type chain struct {
	table      *table
	Name       string
	ChainType  BaseChainType
	Hook       BaseChainHook
	Priority   int
	Policy     string
	MustFlush  bool
	ruleGroups map[RuleGroup][]string
}

// Rules returns the chain's rules, in order.
func (c *chain) Rules() []string {
	groups := make([]RuleGroup, 0, len(c.ruleGroups))
	nRules := 0
	for group := range c.ruleGroups {
		groups = append(groups, group)
		nRules += len(c.ruleGroups[group])
	}
	slices.Sort(groups)
	rules := make([]string, 0, nRules)
	for _, group := range groups {
		rules = append(rules, c.ruleGroups[group]...)
	}
	return rules
}

func parseTemplate() error {
	var err error
	incrementalUpdateTempl, err = template.New("ruleset").Parse(incrementalUpdateTemplText)
	if err != nil {
		return fmt.Errorf("parsing 'incrementalUpdateTemplText': %w", err)
	}
	reloadTempl, err = template.New("ruleset").Parse(reloadTemplText)
	if err != nil {
		return fmt.Errorf("parsing 'reloadTemplText': %w", err)
	}
	return nil
}

// nftApply runs the "nft" command.
func nftApply(ctx context.Context, nftCmd []byte) error {
	ctx, span := otel.Tracer("").Start(ctx, spanPrefix+".nftApply")
	defer span.End()

	if !Enabled() {
		return errors.New("nftables is not enabled")
	}
	cmd := exec.Command(nftPath, "-f", "-")
	stdinPipe, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("getting stdin pipe for nft: %w", err)
	}
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("getting stdout pipe for nft: %w", err)
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("getting stderr pipe for nft: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("starting nft: %w", err)
	}
	if _, err := stdinPipe.Write(nftCmd); err != nil {
		return fmt.Errorf("sending nft commands: %w", err)
	}
	if err := stdinPipe.Close(); err != nil {
		return fmt.Errorf("closing nft input pipe: %w", err)
	}

	stdoutBuf := strings.Builder{}
	if _, err := io.Copy(&stdoutBuf, stdoutPipe); err != nil {
		return fmt.Errorf("reading stdout of nft: %w", err)
	}
	stdout := stdoutBuf.String()
	stderrBuf := strings.Builder{}
	if _, err := io.Copy(&stderrBuf, stderrPipe); err != nil {
		return fmt.Errorf("reading stderr of nft: %w", err)
	}
	stderr := stderrBuf.String()

	err = cmd.Wait()
	if err != nil {
		return fmt.Errorf("running nft: %s %w", stderr, err)
	}
	log.G(ctx).WithFields(log.Fields{"stdout": stdout, "stderr": stderr}).Debug("nftables: updated")
	return nil
}
