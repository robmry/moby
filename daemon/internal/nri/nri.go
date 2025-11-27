package nri

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/containerd/log"
	"github.com/containerd/nri/pkg/adaptation"
	nrilog "github.com/containerd/nri/pkg/log"
	"github.com/moby/moby/api/types/mount"
	"github.com/moby/moby/v2/daemon/config"
	"github.com/moby/moby/v2/daemon/container"
	"github.com/moby/moby/v2/daemon/volume/mounts"
	"github.com/moby/moby/v2/dockerversion"
)

type NRI struct {
	Config

	// mu protects nri - read lock for operations, write lock for sync and shutdown.
	mu  sync.RWMutex
	nri *adaptation.Adaptation
}

type ContainerLister interface {
	List() []*container.Container
}

type Config struct {
	DaemonConfig    config.NRIConfig
	ContainerLister ContainerLister
}

func NewNRI(ctx context.Context, cfg Config) (*NRI, error) {
	n := &NRI{Config: cfg}
	if !n.DaemonConfig.Enable {
		log.G(ctx).Info("NRI is disabled")
		return n, nil
	}

	log.G(ctx).WithFields(log.Fields{
		"pluginPath":       n.DaemonConfig.PluginPath,
		"pluginConfigPath": n.DaemonConfig.PluginConfigPath,
		"socketPath":       n.DaemonConfig.SocketPath,
	}).Info("Starting NRI")
	nrilog.Set(&logShim{})

	var err error
	n.nri, err = adaptation.New("docker", dockerversion.Version, n.syncFn, n.updateFn, nriOptions(n.DaemonConfig)...)
	if err != nil {
		return nil, err
	}
	if err := n.nri.Start(); err != nil {
		return nil, err
	}
	return n, nil
}

func (n *NRI) Shutdown(ctx context.Context) {
	if n.nri == nil {
		return
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	log.G(ctx).Info("Shutting down NRI")
	n.nri.Stop()
}

func (n *NRI) PrepareReload(ctx context.Context, nriCfg config.NRIConfig) (func() error, error) {
	var newNRI *adaptation.Adaptation
	newCfg := n.Config
	newCfg.DaemonConfig = nriCfg

	if nriCfg.Enable {
		var err error
		newNRI, err = adaptation.New("docker", dockerversion.Version, n.syncFn, n.updateFn, nriOptions(newCfg.DaemonConfig)...)
		if err != nil {
			return nil, err
		}
	}

	return func() error {
		n.mu.Lock()
		if n.nri != nil {
			log.G(ctx).Info("Shutting down old NRI instance")
			n.nri.Stop()
		}
		n.Config = newCfg
		n.nri = newNRI
		// Release the lock before starting newNRI, because it'll call back to syncFn
		// which will acquire the lock.
		n.mu.Unlock()

		if newNRI == nil {
			return nil
		}
		return newNRI.Start()
	}, nil
}

func (n *NRI) CreateContainer(ctx context.Context, ctr *container.Container) error {
	n.mu.RLock()
	defer n.mu.RUnlock()
	if n.nri == nil {
		return nil
	}
	ctr.State.Lock()
	defer ctr.State.Unlock()

	nriPod, nriCtr, err := containerToNRI(ctr)
	if err != nil {
		return err
	}

	// TODO(robmry): call RunPodSandbox?

	resp, err := n.nri.CreateContainer(ctx, &adaptation.CreateContainerRequest{
		Pod:       nriPod,
		Container: nriCtr,
	})
	if err != nil {
		return err
	}

	if resp.GetUpdate() != nil {
		return errors.New("container update is not supported")
	}
	if err := applyAdjustments(ctx, ctr, resp.GetAdjust()); err != nil {
		return err
	}
	return nil
}

func (n *NRI) syncFn(ctx context.Context, syncCB adaptation.SyncCB) error {
	// Claim a write lock so containers can't be created/removed until sync is done.
	// The plugin will get create/remove events after the sync, so won't miss anything.
	//
	// If a container's state changes during the sync, the plugin may see already-modified
	// state, then get a change notification with no changes.
	n.mu.Lock()
	defer n.mu.Unlock()

	containers := n.ContainerLister.List()
	nriPods := make([]*adaptation.PodSandbox, 0, len(containers))
	nriCtrs := make([]*adaptation.Container, 0, len(containers))
	for _, ctr := range containers {
		ctr.State.Lock()
		nriPod, nriCtr, err := containerToNRI(ctr)
		ctr.State.Unlock()
		if err != nil {
			return fmt.Errorf("converting container %s to NRI: %w", ctr.ID, err)
		}
		nriPods = append(nriPods, nriPod)
		nriCtrs = append(nriCtrs, nriCtr)
	}
	updates, err := syncCB(ctx, nriPods, nriCtrs)
	if err != nil {
		return fmt.Errorf("synchronizing NRI state: %w", err)
	}
	if len(updates) > 0 {
		return errors.New("container updates during sync are not implemented")
	}
	return nil
}

func (n *NRI) updateFn(context.Context, []*adaptation.ContainerUpdate) ([]*adaptation.ContainerUpdate, error) {
	return nil, errors.New("not implemented")
}

func nriOptions(cfg config.NRIConfig) []adaptation.Option {
	opts := []adaptation.Option{
		adaptation.WithPluginPath(cfg.PluginPath),
		adaptation.WithPluginConfigPath(cfg.PluginConfigPath),
	}
	if cfg.SocketPath == "" {
		opts = append(opts, adaptation.WithDisabledExternalConnections())
	} else {
		opts = append(opts, adaptation.WithSocketPath(cfg.SocketPath))
	}
	return opts
}

func containerToNRI(ctr *container.Container) (*adaptation.PodSandbox, *adaptation.Container, error) {
	nriPod := &adaptation.PodSandbox{
		Id:             ctr.ID,
		Name:           ctr.Name,
		Uid:            "",
		Namespace:      "",
		Labels:         nil,
		Annotations:    nil,
		RuntimeHandler: "",
		Linux:          nil,
		Pid:            0,
		Ips:            nil,
	}

	nriCtr := &adaptation.Container{
		Id:           ctr.ID,
		PodSandboxId: ctr.ID,
		Name:         ctr.Name,
		State:        stateToNRI(ctr.State),
		Labels:       ctr.Config.Labels,
		Annotations:  ctr.HostConfig.Annotations,
		Args:         ctr.Config.Cmd,
		Env:          ctr.Config.Env,
		Hooks:        nil,
		Linux: &adaptation.LinuxContainer{
			Namespaces:     nil,
			Devices:        nil,
			Resources:      nil,
			OomScoreAdj:    nil,
			CgroupsPath:    "",
			IoPriority:     nil,
			SeccompProfile: nil,
			SeccompPolicy:  nil,
		},
		Mounts:        mountPointsToNRI(ctr.MountPoints),
		Pid:           uint32(ctr.Pid),
		Rlimits:       nil,
		CreatedAt:     0,
		StartedAt:     0,
		FinishedAt:    0,
		ExitCode:      0,
		StatusReason:  "",
		StatusMessage: "",
		CDIDevices:    nil,
	}
	return nriPod, nriCtr, nil
}

func stateToNRI(state *container.State) adaptation.ContainerState {
	switch {
	case state.Paused, state.Restarting:
		return adaptation.ContainerState_CONTAINER_PAUSED
	case state.Running:
		return adaptation.ContainerState_CONTAINER_RUNNING
	case !state.FinishedAt.IsZero():
		return adaptation.ContainerState_CONTAINER_EXITED
	}
	return adaptation.ContainerState_CONTAINER_STOPPED
}

func mountPointsToNRI(ctrMPs map[string]*mounts.MountPoint) []*adaptation.Mount {
	if len(ctrMPs) == 0 {
		return nil
	}
	nriMPs := make([]*adaptation.Mount, 0, len(ctrMPs))
	for _, mp := range ctrMPs {
		nriMPs = append(nriMPs, &adaptation.Mount{
			Destination: mp.Destination,
			Type:        string(mp.Type),
			Source:      mp.Source,
			Options:     nil, // TODO(robmry)
		})
	}
	return nriMPs
}

func applyAdjustments(ctx context.Context, ctr *container.Container, adj *adaptation.ContainerAdjustment) error {
	if err := applyEnvVars(ctx, ctr, adj.Env); err != nil {
		return fmt.Errorf("applying environment variable adjustments: %w", err)
	}
	if err := applyMounts(ctx, ctr, adj.Mounts); err != nil {
		return fmt.Errorf("applying mount adjustments: %w", err)
	}
	return nil
}

func applyEnvVars(ctx context.Context, ctr *container.Container, envVars []*adaptation.KeyValue) error {
	if len(envVars) == 0 {
		return nil
	}
	existing := make(map[string]int, len(ctr.Config.Env))
	for i, e := range ctr.Config.Env {
		k, _, _ := strings.Cut(e, "=")
		existing[k] = i
	}
	for _, kv := range envVars {
		if kv.Key == "" {
			return errors.New("empty environment variable key")
		}
		val := kv.Key + "=" + kv.Value
		log.G(ctx).Debugf("Applying NRI env var adjustment: %s", val)
		if i, found := existing[kv.Key]; found {
			ctr.Config.Env[i] = val
		} else {
			ctr.Config.Env = append(ctr.Config.Env, val)
		}
	}
	return nil
}

func applyMounts(ctx context.Context, ctr *container.Container, mounts []*adaptation.Mount) error {
	for _, m := range mounts {
		var ro bool
		for _, opt := range m.Options {
			switch opt {
			case "ro", "readonly": // TODO(robmry): option names?
				ro = true
			default:
				return fmt.Errorf("mount option %q is not supported", opt)
			}
		}
		log.G(ctx).Debugf("Applying NRI mount: type=%s source=%s target=%s ro=%t", m.Type, m.Source, m.Destination, ro)
		ctr.HostConfig.Mounts = append(ctr.HostConfig.Mounts, mount.Mount{
			Type:     mount.Type(m.Type),
			Source:   m.Source,
			Target:   m.Destination,
			ReadOnly: ro,
		})
	}
	return nil
}
