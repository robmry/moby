package nftables

import (
	"context"
	"os"
	"testing"

	"github.com/docker/docker/internal/testutils/netnsutils"
	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
	"gotest.tools/v3/golden"
	"gotest.tools/v3/icmd"
)

func testSetup(t *testing.T) func() {
	t.Helper()
	if err := Enable(); err != nil {
		// Make sure it didn't fail because of a bug in the text/template.
		assert.NilError(t, parseTemplate())
		// If this is not CI, skip.
		if _, ok := os.LookupEnv("CI"); !ok {
			t.Skip("Cannot enable nftables, no 'nft' command in $PATH ?")
		}
		// In CI, nft should always be installed, fail the test.
		t.Fatalf("Failed to enable nftables: %s", err)
	}
	cleanupContext := netnsutils.SetupTestOSContext(t)
	return func() {
		cleanupContext()
		Disable()
	}
}

func applyAndCheck(t *testing.T, tm TableModifier, goldenFilename string) {
	t.Helper()
	err := tm.Apply(context.Background())
	assert.Check(t, err)
	res := icmd.RunCommand("nft", "list", "table", string(tm.Family()), tm.Name())
	res.Assert(t, icmd.Success)
	golden.Assert(t, res.Combined(), goldenFilename)
}

func TestTable(t *testing.T) {
	defer testSetup(t)()

	tbl4, err := NewTable(IPv4, "ipv4_table")
	assert.NilError(t, err)
	tbl6, err := NewTable(IPv6, "ipv6_table")
	assert.NilError(t, err)

	tm4 := tbl4.Modifier()
	tm6 := tbl6.Modifier()

	assert.Check(t, is.Equal(tm4.Family(), IPv4))
	assert.Check(t, is.Equal(tm6.Family(), IPv6))

	// Update nftables and check what happened.
	applyAndCheck(t, tm4, t.Name()+"_created4.golden")
	applyAndCheck(t, tm6, t.Name()+"_created6.golden")
}

func TestChain(t *testing.T) {
	defer testSetup(t)()

	// Create a table.
	tbl, err := NewTable(IPv4, "this_is_a_table")
	assert.NilError(t, err)

	// Create a base chain.
	const bcName = "this_is_a_base_chain"
	tm := tbl.Modifier()
	bcDesc := BaseChainDesc{
		Name:      bcName,
		ChainType: BaseChainTypeFilter,
		Hook:      BaseChainHookForward,
		Priority:  BaseChainPriorityFilter + 10,
		Policy:    "accept",
	}
	tm.Create(bcDesc)
	// Add a rule to the base chain.
	bcCounterRule := RuleDesc{
		Chain: bcName,
		Group: 0,
		Rule:  []string{"counter"},
	}
	tm.Create(bcCounterRule)

	// Add a regular chain.
	const regularChainName = "this_is_a_regular_chain"
	cDesc := ChainDesc{
		Name: regularChainName,
	}
	tm.Create(cDesc)
	// Add a rule to the regular chain.
	cRule := RuleDesc{
		Chain: regularChainName,
		Group: 0,
		Rule:  []string{"counter", "accept"},
	}
	tm.Create(cRule)

	// Add another rule to the base chain.
	bcJumpRule := RuleDesc{
		Chain: bcName,
		Group: 0,
		Rule:  []string{"jump", regularChainName},
	}
	tm.Create(bcJumpRule)

	// Update nftables and check what happened.
	applyAndCheck(t, tm, t.Name()+"_created.golden")

	// Delete a rule from the base chain.
	tm = tbl.Modifier()
	tm.Delete(bcCounterRule)

	/*
		// Check it's an error to delete that rule again. This time, call the delete
		// function directly on a newly retrieved handle.
		err = tbl.Chain(ctx, bcName).DeleteRule(ctx, 0, "counter")
		assert.Check(t, is.ErrorContains(err, "does not exist"))
	*/

	// Update the base chain's policy.
	err = tbl.SetBaseChainPolicy(context.Background(), bcName, "drop")
	assert.Check(t, err)

	/*
		// Check it's an error to set a policy on a regular chain.
		err = tbl.Chain(ctx, regularChainName).SetPolicy("drop")
		assert.Check(t, is.ErrorContains(err, "not a base chain"))
	*/

	// Update nftables and check what happened.
	applyAndCheck(t, tm, t.Name()+"_modified.golden")

	// Delete the base chain.
	tm = tbl.Modifier()
	tm.Delete(bcJumpRule)
	tm.Delete(bcDesc)
	tm.Delete(cRule)
	tm.Delete(cDesc)

	/*
		// Check that it's an error to delete it again.
		err = tbl.DeleteChain(ctx, regularChainName)
		assert.Check(t, is.ErrorContains(err, "does not exist"))
	*/

	// Update nftables and check what happened.
	applyAndCheck(t, tm, t.Name()+"_deleted.golden")
}

/*
func TestDuplicateChain(t *testing.T) {
	// Check that it's an error to add a new base chain with the same name.
	tm = tbl.Modifier()
	tm.Add(BaseChainDesc{
		Name:      bcName,
		ChainType: BaseChainTypeNAT,
		Hook:      BaseChainHookPrerouting,
		Priority:  BaseChainPriorityDstNAT,
		Policy:    "accept",
	})
	err = tm.Apply(context.Background())
	assert.Check(t, is.ErrorContains(err, "already exists"))

	// Check that fetching a non-existent chain returns an invalid ref.
	nsc := tbl.Chain(ctx, "no-such-chain")
	assert.Check(t, !nsc.IsValid(), "'no-such-chain' should be invalid")
}
*/

func TestChainRuleGroups(t *testing.T) {
	defer testSetup(t)()

	tbl, err := NewTable(IPv4, "testtable")
	assert.NilError(t, err)
	tm := tbl.Modifier()
	chainName := "testchain"
	tm.Create(ChainDesc{Name: chainName})
	tm.Create(RuleDesc{
		Chain: chainName,
		Group: 100,
		Rule:  []string{"iifname hello100 counter"},
	})
	tm.Create(RuleDesc{
		Chain: chainName,
		Group: 200,
		Rule:  []string{"iifname hello200 counter"},
	})
	tm.Create(RuleDesc{
		Chain: chainName,
		Group: 100,
		Rule:  []string{"iifname hello101 counter"},
	})
	tm.Create(RuleDesc{
		Chain: chainName,
		Group: 200,
		Rule:  []string{"iifname hello201 counter"},
	})
	tm.Create(RuleDesc{
		Chain: chainName,
		Group: 100,
		Rule:  []string{"iifname hello102 counter"},
	})

	applyAndCheck(t, tm, t.Name()+".golden")
}

func TestVMap(t *testing.T) {
	defer testSetup(t)()

	// Create a table.
	tbl, err := NewTable(IPv6, "this_is_a_table")
	assert.NilError(t, err)
	tm := tbl.Modifier()

	// Create a verdict map.
	const mapName = "this_is_a_vmap"
	tm.Create(VMapDesc{Name: mapName})

	// Add an element.
	tm.Create(VMapElementDesc{
		Name:    mapName,
		Key:     "eth0",
		Verdict: "return",
	})

	/*
		// Check that it's an error to add the element again.
		err = m.AddElement(ctx, "eth0", "return")
		assert.Check(t, is.ErrorContains(err, "already contains element"))
	*/

	// Add another element.
	tm.Create(VMapElementDesc{
		Name:    mapName,
		Key:     "eth1",
		Verdict: "drop",
	})

	// Update nftables and check what happened.
	applyAndCheck(t, tm, t.Name()+"_created.golden")

	// Undo those changes by reversing the commands.
	tmRev := tm.Reverse()

	/*
		// Check it's an error to delete it again.
		err = m.DeleteElement(ctx, "eth1")
		assert.Check(t, is.ErrorContains(err, "does not contain element"))
	*/

	// Update nftables and check what happened.
	applyAndCheck(t, tmRev, t.Name()+"_deleted.golden")
}

func TestSet(t *testing.T) {
	defer testSetup(t)()

	// Create v4 and v6 tables.
	tbl4, err := NewTable(IPv4, "table4")
	assert.NilError(t, err)
	tbl6, err := NewTable(IPv6, "table6")
	assert.NilError(t, err)

	// Create a set in each table.
	const set4Name = "set4"
	tm4 := tbl4.Modifier()
	tm4.Create(PrefixSetDesc{Name: set4Name})
	const set6Name = "set6"
	tm6 := tbl6.Modifier()
	tm6.Create(PrefixSetDesc{Name: set6Name})

	// Add elements to each set.
	tm4.Create(PrefixSetElementDesc{
		Name:   set4Name,
		Prefix: "192.0.2.1/24",
	})
	tm6.Create(PrefixSetElementDesc{
		Name:   set6Name,
		Prefix: "2001:db8::1/64",
	})

	/*
		// Check it's an error to add those elements again.
		err = s4.AddElement(ctx, "192.0.2.1/24")
		assert.Check(t, is.ErrorContains(err, "already contains element"))
		err = s6.AddElement(ctx, "2001:db8::1/64")
		assert.Check(t, is.ErrorContains(err, "already contains element"))
	*/

	// Update nftables and check what happened.
	applyAndCheck(t, tm4, t.Name()+"_created4.golden")
	applyAndCheck(t, tm6, t.Name()+"_created6.golden")

	// Delete elements.
	applyAndCheck(t, tm4.Reverse(), t.Name()+"_deleted4.golden")
	applyAndCheck(t, tm6.Reverse(), t.Name()+"_deleted6.golden")
}

/*
func TestReload(t *testing.T) {
	defer testSetup(t)()
	ctx := context.Background()

	// Create a table with some stuff in it.
	const tableName = "this_is_a_table"
	tbl, err := NewTable(IPv4, tableName)
	assert.NilError(t, err)
	bc, err := tbl.BaseChain(ctx, "a_base_chain", BaseChainTypeFilter, BaseChainHookForward, BaseChainPriorityFilter)
	assert.NilError(t, err)
	err = bc.AppendRule(ctx, 0, "counter")
	assert.NilError(t, err)
	m := tbl.InterfaceVMap(ctx, "this_is_a_vmap")
	err = m.AddElement(ctx, "eth0", "return")
	assert.Check(t, err)
	err = m.AddElement(ctx, "eth1", "return")
	assert.Check(t, err)
	err = tbl.PrefixSet(ctx, "set4").AddElement(ctx, "192.0.2.0/24")
	assert.Check(t, err)
	applyAndCheck(t, tbl, t.Name()+"_created.golden")

	// Delete the underlying nftables table.
	deleteTable := func() {
		t.Helper()
		res := icmd.RunCommand("nft", "delete", "table", string(IPv4), tableName)
		res.Assert(t, icmd.Success)
		res = icmd.RunCommand("nft", "list", "ruleset")
		res.Assert(t, icmd.Success)
		assert.Check(t, is.Equal(res.Combined(), ""))
	}
	deleteTable()

	// Reconstruct the nftables table.
	err = tbl.Reload(context.Background())
	assert.Check(t, err)
	applyAndCheck(t, tbl, t.Name()+"_reloaded.golden")

	// Delete again.
	deleteTable()

	// Check implicit/recovery reload - only deleting something that's gone missing
	// from a vmap/set will trigger this.
	err = m.DeleteElement(ctx, "eth1")
	assert.Check(t, err)
	applyAndCheck(t, tbl, t.Name()+"_recovered.golden")
}


*/
