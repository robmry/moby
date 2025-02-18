package networking

import (
	"fmt"
	"os/exec"
	"strings"
	"testing"

	"github.com/docker/docker/internal/lazyregexp"
	"gotest.tools/v3/assert"
)

// Find the policy in, for example "Chain FORWARD (policy ACCEPT)".
var rePolicy = lazyregexp.New("policy ([A-Za-z]+)")

// FirewalldRunning returns true if "firewall-cmd --state" reports "running".
func FirewalldRunning() bool {
	state, err := exec.Command("firewall-cmd", "--state").CombinedOutput()
	return err == nil && strings.TrimSpace(string(state)) == "running"
}

// SetFilterForwardPolicies sets the default policy for the FORWARD chain in
// the filter tables for both IPv4 and IPv6. The original policy is restored
// using t.Cleanup().
//
// There's only one filter-FORWARD policy, so this won't behave well if used by
// tests running in parallel in a single network namespace that expect different
// behaviour.
func SetFilterForwardPolicies(t *testing.T, firewallBackend string, policy string) {
	t.Helper()
	if firewallBackend == "iptables" {
		setIptablesFFP(t, policy)
		return
	}
	if firewallBackend == "nftables" {
		setNftablesFFP(t, policy)
		return
	}
	t.Fatalf("unknown firewall backend %s", firewallBackend)
}

func setIptablesFFP(t *testing.T, policy string) {
	t.Helper()
	for _, iptablesCmd := range []string{"iptables", "ip6tables"} {
		origPolicy, err := getChainPolicy(t, exec.Command(iptablesCmd, "-L", "FORWARD"))
		assert.NilError(t, err, "failed to get iptables policy")
		if origPolicy == policy {
			continue
		}
		if err := exec.Command(iptablesCmd, "-P", "FORWARD", policy).Run(); err != nil {
			t.Fatalf("Failed to set %s FORWARD policy: %v", iptablesCmd, err)
		}
		t.Cleanup(func() {
			if err := exec.Command(iptablesCmd, "-P", "FORWARD", origPolicy).Run(); err != nil {
				t.Logf("Failed to restore %s FORWARD policy: %v", iptablesCmd, err)
			}
		})
	}
}

func setNftablesFFP(t *testing.T, policy string) {
	t.Helper()
	policy = strings.ToLower(policy)
	for _, family := range []string{"ip", "ip6"} {
		origPolicy, err := getChainPolicy(t, exec.Command("nft", "list chain "+family+" docker-bridges filter-FORWARD"))
		assert.NilError(t, err, "failed to get nftables policy")
		if origPolicy == policy {
			continue
		}
		const ruleFmt = "add chain %s docker-bridges filter-FORWARD { policy %s; }"
		if err := exec.Command("nft", fmt.Sprintf(ruleFmt, family, policy)).Run(); err != nil {
			t.Fatalf("Failed to set %s filter-FORWARD policy: %v", family, err)
		}
		t.Cleanup(func() {
			if err := exec.Command("nft", fmt.Sprintf(ruleFmt, family, origPolicy)).Run(); err != nil {
				t.Logf("Failed to restore %s filter-FORWARD policy: %v", family, err)
			}
		})
	}
}

func getChainPolicy(t *testing.T, cmd *exec.Cmd) (string, error) {
	t.Helper()
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("getting policy: %w", err)
	}
	opMatch := rePolicy.FindSubmatch(out)
	if len(opMatch) != 2 {
		return "", fmt.Errorf("searching for policy: %w", err)
	}
	return string(opMatch[1]), nil
}
