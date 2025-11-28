package nri

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/containerd/nri/pkg/api"
	"github.com/moby/moby/api/types/mount"
	"github.com/moby/moby/client"
	"github.com/moby/moby/v2/integration/internal/container"
	"github.com/moby/moby/v2/internal/testutil"
	"github.com/moby/moby/v2/internal/testutil/daemon"
	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
	"gotest.tools/v3/skip"
)

func TestNRIContainerCreateEnvVarMod(t *testing.T) {
	skip.If(t, testEnv.IsRemoteDaemon, "cannot run daemon when remote daemon")
	skip.If(t, testEnv.DaemonInfo.OSType == "windows")
	skip.If(t, testEnv.IsRootless)

	ctx := testutil.StartSpan(baseContext, t)

	tmp := t.TempDir()
	sockPath := filepath.Join(tmp, "nri.sock")

	d := daemon.New(t)
	d.StartWithBusybox(ctx, t,
		"--nri-opts=enable=true,socket-path="+sockPath,
		"--iptables=false", "--ip6tables=false",
	)
	defer d.Stop(t)
	c := d.NewClientT(t)

	testcases := []struct {
		name         string
		ctrCreateAdj *api.ContainerAdjustment
		expEnv       string
	}{
		{
			name:         "env/set",
			ctrCreateAdj: &api.ContainerAdjustment{Env: []*api.KeyValue{{Key: "NRI_SAYS", Value: "hello"}}},
			expEnv:       "NRI_SAYS=hello",
		},
		{
			name:         "env/modify",
			ctrCreateAdj: &api.ContainerAdjustment{Env: []*api.KeyValue{{Key: "HOSTNAME", Value: "nrivictim"}}},
			expEnv:       "HOSTNAME=nrivictim",
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			startBuiltinPlugin(ctx, t, builtinPluginConfig{
				pluginName:   "nri-test-plugin",
				pluginIdx:    "00",
				sockPath:     sockPath,
				ctrCreateAdj: tc.ctrCreateAdj,
			})

			ctrId := container.Run(ctx, t, c)
			defer func() { _, _ = c.ContainerRemove(ctx, ctrId, client.ContainerRemoveOptions{Force: true}) }()

			inspect, err := c.ContainerInspect(ctx, ctrId, client.ContainerInspectOptions{})
			if assert.Check(t, err) {
				assert.Check(t, is.Contains(inspect.Container.Config.Env, tc.expEnv))
			}
		})
	}
}

func TestNRIContainerCreateAddMount(t *testing.T) {
	skip.If(t, testEnv.IsRemoteDaemon, "cannot run daemon when remote daemon")
	skip.If(t, testEnv.DaemonInfo.OSType == "windows")
	skip.If(t, testEnv.IsRootless)

	ctx := testutil.StartSpan(baseContext, t)

	tmp := t.TempDir()
	sockPath := filepath.Join(tmp, "nri.sock")

	d := daemon.New(t)
	d.StartWithBusybox(ctx, t,
		"--nri-opts=enable=true,socket-path="+sockPath,
		"--iptables=false", "--ip6tables=false",
	)
	defer d.Stop(t)
	c := d.NewClientT(t)

	// Create and populate a directory for containers to mount.
	dirToMount := t.TempDir()
	if err := os.WriteFile(filepath.Join(dirToMount, "testfile.txt"), []byte("hello\n"), 0o644); err != nil {
		assert.NilError(t, err)
	}
	const mountPoint = "/mountpoint"
	const ctrTestFile = "/mountpoint/testfile.txt"
	exitOk := 0
	exitFail := 1

	// Create and populate a volume.
	const volName = "nri-test-volume"
	_, err := c.VolumeCreate(ctx, client.VolumeCreateOptions{Name: volName})
	assert.NilError(t, err)
	defer func() {
		_, _ = c.VolumeRemove(ctx, volName, client.VolumeRemoveOptions{Force: true})
	}()
	// Populate the volume with a test file.
	_ = container.Run(ctx, t, c,
		container.WithAutoRemove,
		container.WithMount(mount.Mount{Type: "volume", Source: volName, Target: mountPoint}),
		container.WithCmd("sh", "-c", "echo hello > "+ctrTestFile),
	)

	testcases := []struct {
		name         string
		ctrCreateAdj *api.ContainerAdjustment

		expMountRead  *int
		expMountWrite *int
	}{
		{
			name: "mount/bind/ro",
			ctrCreateAdj: &api.ContainerAdjustment{Mounts: []*api.Mount{{
				Type:        "bind",
				Source:      dirToMount,
				Destination: mountPoint,
				Options:     []string{"ro"},
			}}},
			expMountRead:  &exitOk,
			expMountWrite: &exitFail,
		},
		{
			name: "mount/bind/rw",
			ctrCreateAdj: &api.ContainerAdjustment{Mounts: []*api.Mount{{
				Type:        "bind",
				Source:      dirToMount,
				Destination: mountPoint,
			}}},
			expMountRead:  &exitOk,
			expMountWrite: &exitOk,
		},
		{
			name: "mount/volume/ro",
			ctrCreateAdj: &api.ContainerAdjustment{Mounts: []*api.Mount{{
				Type:        "volume",
				Source:      volName,
				Destination: mountPoint,
				Options:     []string{"ro"},
			}}},
			expMountRead:  &exitOk,
			expMountWrite: &exitFail,
		},
		{
			name: "mount/volume/rw",
			ctrCreateAdj: &api.ContainerAdjustment{Mounts: []*api.Mount{{
				Type:        "volume",
				Source:      volName,
				Destination: mountPoint,
			}}},
			expMountRead:  &exitOk,
			expMountWrite: &exitOk,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			startBuiltinPlugin(ctx, t, builtinPluginConfig{
				pluginName:   "nri-test-plugin",
				pluginIdx:    "00",
				sockPath:     sockPath,
				ctrCreateAdj: tc.ctrCreateAdj,
			})

			ctrId := container.Run(ctx, t, c)
			defer func() { _, _ = c.ContainerRemove(ctx, ctrId, client.ContainerRemoveOptions{Force: true}) }()

			if tc.expMountRead != nil {
				res, err := container.Exec(ctx, c, ctrId, []string{"cat", ctrTestFile})
				if assert.Check(t, err) {
					assert.Check(t, is.Equal(res.ExitCode, *tc.expMountRead))
					assert.Check(t, is.Equal(res.Stdout(), "hello\n"))
				}
			}
			if tc.expMountWrite != nil {
				res, err := container.Exec(ctx, c, ctrId, []string{"touch", ctrTestFile})
				if assert.Check(t, err) {
					assert.Check(t, is.Equal(res.ExitCode, *tc.expMountWrite))
				}
			}
		})
	}
}
