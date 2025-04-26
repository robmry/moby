//go:build linux

package nftabler

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/docker/docker/internal/testutils/netnsutils"
	"github.com/docker/docker/libnetwork/drivers/bridge/internal/firewaller"
	"github.com/docker/docker/libnetwork/internal/nftables"
	"github.com/vishvananda/netlink"
	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
)

func TestMirroredWSL2Workaround(t *testing.T) {
	ok := nftables.Enable()
	assert.Assert(t, ok)
	defer nftables.Disable()

	for _, tc := range []struct {
		desc             string
		loopback0        bool
		userlandProxy    bool
		wslinfoPerm      os.FileMode // 0 for no-file
		expLoopback0Rule bool
	}{
		{
			desc: "No loopback0",
		},
		{
			desc:             "WSL2 mirrored",
			loopback0:        true,
			userlandProxy:    true,
			wslinfoPerm:      0o777,
			expLoopback0Rule: true,
		},
		{
			desc:          "loopback0 but wslinfo not executable",
			loopback0:     true,
			userlandProxy: true,
			wslinfoPerm:   0o666,
		},
		{
			desc:          "loopback0 but no wslinfo",
			loopback0:     true,
			userlandProxy: true,
		},
		{
			desc:        "loopback0 but no userland proxy",
			loopback0:   true,
			wslinfoPerm: 0o777,
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			defer netnsutils.SetupTestOSContext(t)()
			restoreWslinfoPath := simulateWSL2MirroredMode(t, tc.loopback0, tc.wslinfoPerm)
			defer restoreWslinfoPath()

			_, err := NewNftabler(context.Background(), firewaller.Config{
				IPv4:    true,
				Hairpin: !tc.userlandProxy,
			})
			assert.NilError(t, err)

			out, err := exec.Command("nft", "list", "chain", "ip", dockerTable, natChain).CombinedOutput()
			assert.NilError(t, err)
			if tc.expLoopback0Rule {
				assert.Check(t, is.Contains(string(out), "loopback0"))
			} else {
				assert.Check(t, !strings.Contains(string(out), "loopback0"), "did not expect WSL2 loopback rule")
			}
		})
	}
}

// simulateWSL2MirroredMode simulates the WSL2 mirrored mode by creating a
// loopback0 interface and optionally creating a wslinfo file with the given
// permissions.
// A clean up function is returned and will restore the original wslinfoPath
// used within the 'bridge' package. The loopback0 interface isn't cleaned up.
// Instead this function should be called from a disposable network namespace.
func simulateWSL2MirroredMode(t *testing.T, loopback0 bool, wslinfoPerm os.FileMode) func() {
	if loopback0 {
		iface := &netlink.Dummy{
			LinkAttrs: netlink.LinkAttrs{
				Name: "loopback0",
			},
		}
		err := netlink.LinkAdd(iface)
		assert.NilError(t, err)
	}

	wslinfoPathOrig := firewaller.WslinfoPath
	if wslinfoPerm != 0 {
		tmpdir := t.TempDir()
		p := filepath.Join(tmpdir, "wslinfo")
		err := os.WriteFile(p, []byte("#!/bin/sh\necho dummy file\n"), wslinfoPerm)
		assert.NilError(t, err)
		firewaller.WslinfoPath = p
	}

	return func() {
		firewaller.WslinfoPath = wslinfoPathOrig
	}
}
