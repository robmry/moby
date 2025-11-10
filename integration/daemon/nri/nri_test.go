package nri

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/moby/moby/client"
	"github.com/moby/moby/v2/integration/internal/container"
	"github.com/moby/moby/v2/internal/testutil"
	"github.com/moby/moby/v2/internal/testutil/daemon"
	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
	"gotest.tools/v3/skip"
)

func TestNRI(t *testing.T) {
	skip.If(t, testEnv.IsRemoteDaemon, "cannot run daemon when remote daemon")
	skip.If(t, testEnv.DaemonInfo.OSType == "windows")
	skip.If(t, testEnv.IsRootless)

	ctx := testutil.StartSpan(baseContext, t)

	tmp := t.TempDir()
	sockPath := filepath.Join(tmp, "nri.sock")
	dirToMount := t.TempDir()
	if err := os.WriteFile(filepath.Join(dirToMount, "nri-file.txt"), []byte("hello world!"), 0o644); err != nil {
		assert.NilError(t, err)
	}

	d := daemon.New(t)
	d.StartWithBusybox(ctx, t,
		"--nri=true", "--nri-socket="+sockPath,
		"--iptables=false", "--ip6tables=false",
	)
	defer d.Stop(t)

	c := d.NewClientT(t)

	p, err := startPlugin(ctx, t, config{
		pluginName: "nritestplugin",
		pluginIdx:  "00",
		sockPath:   sockPath,
		dirToMount: dirToMount,
	})
	assert.NilError(t, err)
	defer p.stub.Stop()

	ctrId := container.Run(ctx, t, c)
	defer func() { _, _ = c.ContainerRemove(ctx, ctrId, client.ContainerRemoveOptions{Force: true}) }()

	inspect, err := c.ContainerInspect(ctx, ctrId, client.ContainerInspectOptions{})
	assert.NilError(t, err)
	assert.Check(t, is.Contains(inspect.Container.Config.Env, "HOSTNAME=nrivictim"))
	assert.Check(t, is.Contains(inspect.Container.Config.Env, "NRI_SAYS=hello world!"))
}
