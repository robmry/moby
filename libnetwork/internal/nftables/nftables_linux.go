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
)

var (
	nftPath    string
	enableOnce sync.Once
)

type BaseChainType string

const (
	BaseChainTypeFilter BaseChainType = "filter"
	BaseChainTypeRoute  BaseChainType = "route"
	BaseChainTypeNAT    BaseChainType = "nat"
)

type BaseChainHook string

const (
	BaseChainHookIngress     BaseChainHook = "ingress"
	BaseChainHookPrerouting  BaseChainHook = "prerouting"
	BaseChainHookInput       BaseChainHook = "input"
	BaseChainHookForward     BaseChainHook = "forward"
	BaseChainHookOutput      BaseChainHook = "output"
	BaseChainHookPostrouting BaseChainHook = "postrouting"
)

// Standard priority values (not for the bridge family, those are different).
const (
	BaseChainPriorityRaw      = -300
	BaseChainPriorityMangle   = -150
	BaseChainPriorityDstNAT   = -100
	BaseChainPriorityFilter   = 0
	BaseChainPrioritySecurity = 50
	BaseChainPrioritySrcNAT   = 100
)

type Family string

const (
	IPv4 Family = "ip"
	IPv6 Family = "ip6"
)

type BaseChainConfig struct {
	Family   Family
	Table    string
	Chain    string
	Type     BaseChainType
	Hook     BaseChainHook
	Priority int
}

type nftType string

const (
	nftTypeIPv4Addr    nftType = "ipv4_addr"
	nftTypeIPv6Addr    nftType = "ipv6_addr"
	nftTypeEtherAddr   nftType = "ether_addr"
	nftTypeInetProto   nftType = "inet_proto"
	nftTypeInetService nftType = "inet_service"
	nftTypeMark        nftType = "mark"
	nftTypeIfname      nftType = "ifname"
)

func Enable() bool {
	enableOnce.Do(func() {
		path, err := exec.LookPath("nft")
		if err != nil {
			log.G(context.TODO()).WithError(err).Warnf("failed to find nft tool")
		}
		nftPath = path
	})
	return nftPath != ""
}

func Enabled() bool {
	return nftPath != ""
}

//////////////////////////////
// Tables

type table struct {
	Name   string
	Family Family

	VMaps  map[string]*vMap
	Sets   map[string]*set
	Chains map[string]*chain

	DeleteChainCommands []string
}

type TableRef struct {
	t *table
}

func NewTable(family Family, name string) (TableRef, error) {
	t := TableRef{
		t: &table{
			Name:   name,
			Family: family,
			VMaps:  map[string]*vMap{},
			Sets:   map[string]*set{},
			Chains: map[string]*chain{},
		},
	}
	// Flush the table in case an older incarnation of the daemon populated it.
	// Maps, sets and empty chains in the table will be cleared if they're re-added. Until
	// then, they're not used anyway.
	if err := nftApply(context.Background(),
		[]byte(fmt.Sprintf("table %[1]s %[2]s {}; flush table %[1]s %[2]s", family, name))); err != nil {
		return TableRef{}, fmt.Errorf("creating nftables table %s %s: %w", family, name, err)
	}
	return t, nil
}

func (t TableRef) Family() Family {
	return t.t.Family
}

// templateText is used with text/template to generate an nftables command file (which will be
// applied atomically) to:
//   - declare the table and its sets/maps with empty versions of modified chains, so that
//     these things can be flushed/deleted if they don't yet exist.
//   - flush each newly created set/map, so that deleted entries left behind by an old daemon
//     can't interfere.
//   - delete deleted map/set elements
//   - flush modified chains
//   - delete deleted chains
//   - re-populate modified chains
//   - add new map/set elements
const templateText = `{{$family := .Family}}{{$tableName := .Name}}
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
	{{range .Chains}}{{if .Dirty}}chain {{.Name}} {
		{{if .ChainType}}type {{.ChainType}} hook {{.Hook}} priority {{.Priority}}; policy {{.Policy}}{{end}}
	} ; {{end}}{{end}}
}
{{range .VMaps}}{{if .Dirty}}flush map {{$family}} {{$tableName}} {{.Name}}
{{end}}{{end}}
{{range .Sets}}{{if .Dirty}}flush set {{$family}} {{$tableName}} {{.Name}}
{{end}}{{end}}
{{range .Chains}}{{if .Dirty}}flush chain {{$family}} {{$tableName}} {{.Name}}
{{end}}{{end}}
{{range .VMaps}}{{if .DeletedElements}}delete element {{$family}} {{$tableName}} {{.Name}} { {{range $k,$v := .DeletedElements}}{{$k}}, {{end}} }
{{end}}{{end}}
{{range .Sets}}{{if .DeletedElements}}delete element {{$family}} {{$tableName}} {{.Name}} { {{range $k,$v := .DeletedElements}}{{$k}}, {{end}} }
{{end}}{{end}}
{{range .DeleteChainCommands}}{{.}}
{{end}}
table {{$family}} {{$tableName}} {
	{{range .Chains}}{{if .Dirty}}chain {{.Name}} {
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

/* Template for replacing the whole table - maybe for a reload, maybe delete ...
// templateText is used with text/template to generate an nftables command file (which will be
// applied atomically) to:
//   - declare the table, so that it can be flushed if it doesn't yet exist (including each
//     map/set that's in the config so that, if they don't already exist, they can be flushed)
//   - flush each set/map, so that deleted entries won't be there when they're re-populated
//   - flush the table, which deletes rules (but not chains, sets or maps)
//   - create the new table, populating maps/sets/chains
//   - delete chains that are no longer needed
const templateText = `{{$family := .Family}}{{$tableName := .Name}}
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
}
flush table {{.Family}} {{.Name}}
{{range .VMaps}}flush map {{$family}} {{$tableName}} {{.Name}}
delete map {{$family}} {{$tableName}} {{.Name}}
{{end}}
{{range .Sets}}flush set {{$family}} {{$tableName}} {{.Name}}
delete set {{$family}} {{$tableName}} {{.Name}}
{{end}}
table {{$family}} {{$tableName}} {
       {{range .VMaps}}map {{.Name}} {
               type {{.ElementType}} : verdict
               {{if len .Flags}}flags{{range .Flags}} {{.}}{{end}}{{end}}
               {{if len .Elements}}elements = { {{range .Elements}}
                       {{.Key}} : {{.Value}},{{end}}
               }{{end}}
       }
       {{end}}
       {{range .Sets}}set {{.Name}} {
               type {{.ElementType}}
               {{if len .Flags}}flags{{range .Flags}} {{.}}{{end}}{{end}}
               {{if len .Elements}}elements = { {{range .Elements}}
                       {{.}},{{end}}
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
{{range .DeleteChainCommands}}{{.}}
{{end}}
`
*/

func (t TableRef) Apply(ctx context.Context) error {
	var buf bytes.Buffer
	templ, err := template.New("ruleset").Parse(templateText)
	if err != nil {
		return fmt.Errorf("failed to parse template nft ruleset: %w", err)
	}
	if err := templ.Execute(&buf, t.t); err != nil {
		return fmt.Errorf("failed to execute template nft ruleset: %w", err)
	}
	err = nftApply(ctx, buf.Bytes())
	if err != nil {
		var sb strings.Builder
		for i, line := range bytes.SplitAfter(buf.Bytes(), []byte("\n")) {
			sb.WriteString(strconv.Itoa(i + 1))
			sb.WriteString(":\t")
			sb.Write(line)
		}
		log.G(ctx).Error("nftables: failed to update nftables:\n", sb.String(), "\n", err)
		return err
	}
	t.t.DeleteChainCommands = t.t.DeleteChainCommands[:0]
	for _, c := range t.t.Chains {
		c.Dirty = false
	}
	for _, m := range t.t.VMaps {
		m.Dirty = false
		m.AddedElements = map[string]string{}
		m.DeletedElements = map[string]struct{}{}
	}
	for _, s := range t.t.Sets {
		s.Dirty = false
		s.AddedElements = map[string]struct{}{}
		s.DeletedElements = map[string]struct{}{}
	}
	return nil
}

//////////////////////////////
// Chains

type RuleGroup int

type chain struct {
	table      *table
	Name       string
	ChainType  BaseChainType
	Hook       BaseChainHook
	Priority   int
	Policy     string
	Dirty      bool
	ruleGroups map[RuleGroup][]string
}

type ChainRef struct {
	c *chain
}

func (t TableRef) BaseChain(name string, chainType BaseChainType, hook BaseChainHook, priority int) (ChainRef, error) {
	if _, ok := t.t.Chains[name]; ok {
		return ChainRef{}, fmt.Errorf("chain %q already exists", name)
	}
	c := &chain{
		table:      t.t,
		Name:       name,
		ChainType:  chainType,
		Hook:       hook,
		Priority:   priority,
		Policy:     "accept",
		Dirty:      true,
		ruleGroups: map[RuleGroup][]string{},
	}
	t.t.Chains[name] = c
	log.G(context.TODO()).WithFields(log.Fields{
		"family": t.t.Family,
		"table":  t.t.Name,
		"chain":  name,
		"type":   chainType,
		"hook":   hook,
		"prio":   priority,
	}).Debug("nftables: created base chain")
	return ChainRef{c: c}, nil
}

func (t TableRef) Chain(name string) ChainRef {
	c, ok := t.t.Chains[name]
	if !ok {
		c = &chain{
			table:      t.t,
			Name:       name,
			Dirty:      true,
			ruleGroups: map[RuleGroup][]string{},
		}
		t.t.Chains[name] = c
	}
	log.G(context.TODO()).WithFields(log.Fields{
		"family": t.t.Family,
		"table":  t.t.Name,
		"chain":  name,
	}).Debug("nftables: created chain")
	return ChainRef{c: c}
}

type ChainUpdateFunc func(RuleGroup, string, ...interface{}) error

func (t TableRef) ChainUpdateFunc(name string, enable bool) ChainUpdateFunc {
	c := t.Chain(name)
	if enable {
		return c.AppendRule
	}
	return c.DeleteRule
}

func (t TableRef) DeleteChain(name string) error {
	if _, ok := t.t.Chains[name]; !ok {
		return fmt.Errorf("chain %q does not exist", name)
	}
	delete(t.t.Chains, name)
	t.t.DeleteChainCommands = append(t.t.DeleteChainCommands,
		fmt.Sprintf("delete chain %s %s %s", t.t.Family, t.t.Name, name))
	log.G(context.TODO()).WithFields(log.Fields{
		"family": t.t.Family,
		"table":  t.t.Name,
		"chain":  name,
	}).Debug("nftables: deleted chain")
	return nil
}

func (c ChainRef) SetPolicy(policy string) error {
	if c.c.ChainType == "" {
		return errors.New("not a base chain")
	}
	c.c.Policy = policy
	c.c.Dirty = true
	return nil
}

func (c ChainRef) AppendRule(group RuleGroup, rule string, args ...interface{}) error {
	if len(args) > 0 {
		rule = fmt.Sprintf(rule, args...)
	}
	if rg, ok := c.c.ruleGroups[group]; ok && slices.Contains(rg, rule) {
		return fmt.Errorf("rule %q already exists", rule)
	}
	c.c.ruleGroups[group] = append(c.c.ruleGroups[group], rule)
	c.c.Dirty = true
	log.G(context.TODO()).WithFields(log.Fields{
		"family": c.c.table.Family,
		"table":  c.c.table.Name,
		"chain":  c.c.Name,
		"group":  group,
		"rule":   rule,
	}).Debug("nftables: appended rule")
	return nil
}

func (c ChainRef) DeleteRule(group RuleGroup, rule string, args ...interface{}) error {
	if len(args) > 0 {
		rule = fmt.Sprintf(rule, args...)
	}
	rg, ok := c.c.ruleGroups[group]
	if !ok {
		return fmt.Errorf("rule group %d does not exist", group)
	}
	origLen := len(rg)
	c.c.ruleGroups[group] = slices.DeleteFunc(rg, func(r string) bool { return r == rule })
	if len(c.c.ruleGroups[group]) == origLen {
		return fmt.Errorf("rule %q does not exist", rule)
	}
	c.c.Dirty = true
	log.G(context.TODO()).WithFields(log.Fields{
		"family": c.c.table.Family,
		"table":  c.c.table.Name,
		"chain":  c.c.Name,
		"rule":   rule,
	}).Debug("nftables: deleted rule")
	return nil
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

//////////////////////////////
// VMaps

type vMap struct {
	table           *table
	Name            string
	ElementType     nftType
	Flags           []string
	Elements        map[string]string
	Dirty           bool // New vMap, needs to be flushed (not set when elements are added/deleted).
	AddedElements   map[string]string
	DeletedElements map[string]struct{}
}

type VMapRef struct {
	v *vMap
}

func (t TableRef) InterfaceVMap(name string) VMapRef {
	if vmap, ok := t.t.VMaps[name]; ok {
		return VMapRef{vmap}
	}
	vmap := &vMap{
		table:           t.t,
		Name:            name,
		ElementType:     nftTypeIfname,
		Elements:        map[string]string{},
		AddedElements:   map[string]string{},
		DeletedElements: map[string]struct{}{},
		Dirty:           true,
	}
	t.t.VMaps[name] = vmap
	log.G(context.TODO()).WithFields(log.Fields{
		"family": t.t.Family,
		"table":  t.t.Name,
		"vmap":   name,
	}).Debug("nftables: created interface vmap")
	return VMapRef{vmap}
}

func (v VMapRef) AddElement(key string, verdict string) error {
	if _, ok := v.v.Elements[key]; ok {
		return fmt.Errorf("verdict map already contains element %q", key)
	}
	v.v.Elements[key] = verdict
	v.v.AddedElements[key] = verdict
	log.G(context.TODO()).WithFields(log.Fields{
		"family":  v.v.table.Family,
		"table":   v.v.table.Name,
		"vmap":    v.v.Name,
		"key":     key,
		"verdict": verdict,
	}).Debug("nftables: added vmap element")
	return nil
}

func (v VMapRef) DeleteElement(key string) error {
	if _, ok := v.v.Elements[key]; !ok {
		return fmt.Errorf("verdict map does not contain element %q", key)
	}
	delete(v.v.Elements, key)
	v.v.DeletedElements[key] = struct{}{}
	log.G(context.TODO()).WithFields(log.Fields{
		"family": v.v.table.Family,
		"table":  v.v.table.Name,
		"vmap":   v.v.Name,
		"key":    key,
	}).Debug("nftables: deleted vmap element")
	return nil
}

//////////////////////////////
// Sets

type set struct {
	table           *table
	Name            string
	ElementType     nftType
	Flags           []string
	Elements        map[string]struct{}
	Dirty           bool // New set, needs to be flushed (not set when elements are added/deleted).
	AddedElements   map[string]struct{}
	DeletedElements map[string]struct{}
}

type SetRef struct {
	s *set
}

func (t TableRef) PrefixSet(name string) SetRef {
	if s, ok := t.t.Sets[name]; ok {
		return SetRef{s}
	}
	s := &set{
		table:           t.t,
		Name:            name,
		Elements:        map[string]struct{}{},
		ElementType:     nftTypeIPv4Addr,
		Flags:           []string{"interval"},
		Dirty:           true,
		AddedElements:   map[string]struct{}{},
		DeletedElements: map[string]struct{}{},
	}
	if t.t.Family == IPv6 {
		s.ElementType = nftTypeIPv6Addr
	}
	t.t.Sets[name] = s
	log.G(context.TODO()).WithFields(log.Fields{
		"family": t.t.Family,
		"table":  t.t.Name,
		"set":    name,
	}).Debug("nftables: created set")
	return SetRef{s}
}

func (s SetRef) AddElement(element string) error {
	if _, ok := s.s.Elements[element]; ok {
		return fmt.Errorf("set already contains element %q", element)
	}
	s.s.Elements[element] = struct{}{}
	s.s.AddedElements[element] = struct{}{}
	log.G(context.TODO()).WithFields(log.Fields{
		"family":  s.s.table.Family,
		"table":   s.s.table.Name,
		"set":     s.s.Name,
		"element": element,
	}).Debug("nftables: added set element")
	return nil
}

func (s SetRef) DeleteElement(element string) error {
	if _, ok := s.s.Elements[element]; !ok {
		return fmt.Errorf("set does not contain element %q", element)
	}
	delete(s.s.Elements, element)
	s.s.DeletedElements[element] = struct{}{}
	log.G(context.TODO()).WithFields(log.Fields{
		"family":  s.s.table.Family,
		"table":   s.s.table.Name,
		"set":     s.s.Name,
		"element": element,
	}).Debug("nftables: deleted set element")
	return nil
}

//////////////////////////////
// Ruleset

func nftApply(ctx context.Context, nftCmd []byte) error {
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
		return fmt.Errorf("getting stout pipe for nft: %w", err)
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
