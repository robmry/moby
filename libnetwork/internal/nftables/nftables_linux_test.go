package nftables

import (
	"testing"

	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
)

func TestChainRules(t *testing.T) {
	tbl, err := NewTable(IPv4, "testtable")
	assert.NilError(t, err)
	c := tbl.Chain("testchain")
	c.AppendRule(100, "hello100")
	c.AppendRule(200, "hello200")
	c.AppendRule(100, "hello101")
	c.AppendRule(200, "hello201")
	c.AppendRule(100, "hello102")

	assert.Check(t, is.DeepEqual(c.c.Rules(), []string{
		"hello100", "hello101", "hello102",
		"hello200", "hello201",
	}))
}
