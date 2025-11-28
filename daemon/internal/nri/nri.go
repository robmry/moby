package nri

import (
	"context"
	"errors"
	"sync"

	"github.com/containerd/log"
	"github.com/containerd/nri/pkg/adaptation"
	nrilog "github.com/containerd/nri/pkg/log"
	"github.com/moby/moby/v2/daemon/config"
	"github.com/moby/moby/v2/daemon/container"
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

func (n *NRI) syncFn(ctx context.Context, syncCB adaptation.SyncCB) error {
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
