/*
  Based on https://github.com/containerd/nri/blob/main/plugins/template/ - which is ...

   Copyright The containerd Authors.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package nri

import (
	"context"
	"errors"
	"testing"

	"github.com/containerd/log"
	"github.com/containerd/nri/pkg/api"
	"github.com/containerd/nri/pkg/stub"
	"gotest.tools/v3/assert"
)

type config struct {
	CfgParam1 string `json:"cfgParam1"`
}

type plugin struct {
	stub stub.Stub
	mask stub.EventMask
	logG func(context.Context) *log.Entry
}

var cfg config

func (p *plugin) Configure(ctx context.Context, config, runtime, version string) (stub.EventMask, error) {
	p.logG(ctx).Infof("Connected to %s/%s...", runtime, version)

	if config != "" {
		return 0, errors.New("plugin config from yaml is not implemented")
	}
	return 0, nil
}

func (p *plugin) Synchronize(ctx context.Context, pods []*api.PodSandbox, containers []*api.Container) ([]*api.ContainerUpdate, error) {
	p.logG(ctx).Infof("Synchronized state with the runtime (%d pods, %d containers)...",
		len(pods), len(containers))
	return nil, nil
}

func (p *plugin) Shutdown(ctx context.Context) {
	p.logG(ctx).Info("Runtime shutting down...")
}

func (p *plugin) RunPodSandbox(ctx context.Context, pod *api.PodSandbox) error {
	p.logG(ctx).Infof("Started pod %s/%s...", pod.GetNamespace(), pod.GetName())
	return nil
}

func (p *plugin) StopPodSandbox(ctx context.Context, pod *api.PodSandbox) error {
	p.logG(ctx).Infof("Stopped pod %s/%s...", pod.GetNamespace(), pod.GetName())
	return nil
}

func (p *plugin) RemovePodSandbox(ctx context.Context, pod *api.PodSandbox) error {
	p.logG(ctx).Infof("Removed pod %s/%s...", pod.GetNamespace(), pod.GetName())
	return nil
}

func (p *plugin) CreateContainer(ctx context.Context, pod *api.PodSandbox, ctr *api.Container) (*api.ContainerAdjustment, []*api.ContainerUpdate, error) {
	p.logG(ctx).Infof("Creating container %s/%s/%s...", pod.GetNamespace(), pod.GetName(), ctr.GetName())

	//
	// This is the container creation request handler. Because the container
	// has not been created yet, this is the lifecycle event which allows you
	// the largest set of changes to the container's configuration, including
	// some of the later immutable parameters. Take a look at the adjustment
	// functions in pkg/api/adjustment.go to see the available controls.
	//
	// In addition to reconfiguring the container being created, you are also
	// allowed to update other existing containers. Take a look at the update
	// functions in pkg/api/update.go to see the available controls.
	//

	adjustment := &api.ContainerAdjustment{
		Annotations: nil,
		Mounts:      nil,
		Env: []*api.KeyValue{
			{
				Key:   "HOSTNAME",
				Value: "nrivictim",
			},
			{
				Key:   "NRI_SAYS",
				Value: "hello world!",
			},
		},
		Hooks:   nil,
		Linux:   nil,
		Rlimits: nil,
	}
	updates := []*api.ContainerUpdate{}

	return adjustment, updates, nil
}

func (p *plugin) PostCreateContainer(ctx context.Context, pod *api.PodSandbox, ctr *api.Container) error {
	p.logG(ctx).Infof("Created container %s/%s/%s...", pod.GetNamespace(), pod.GetName(), ctr.GetName())
	return nil
}

func (p *plugin) StartContainer(ctx context.Context, pod *api.PodSandbox, ctr *api.Container) error {
	p.logG(ctx).Infof("Starting container %s/%s/%s...", pod.GetNamespace(), pod.GetName(), ctr.GetName())
	return nil
}

func (p *plugin) PostStartContainer(ctx context.Context, pod *api.PodSandbox, ctr *api.Container) error {
	p.logG(ctx).Infof("Started container %s/%s/%s...", pod.GetNamespace(), pod.GetName(), ctr.GetName())
	return nil
}

func (p *plugin) UpdateContainer(ctx context.Context, pod *api.PodSandbox, ctr *api.Container, r *api.LinuxResources) ([]*api.ContainerUpdate, error) {
	p.logG(ctx).Infof("Updating container %s/%s/%s...", pod.GetNamespace(), pod.GetName(), ctr.GetName())

	//
	// This is the container update request handler. You can make changes to
	// the container update before it is applied. Take a look at the functions
	// in pkg/api/update.go to see the available controls.
	//
	// In addition to altering the pending update itself, you are also allowed
	// to update other existing containers.
	//

	updates := []*api.ContainerUpdate{}

	return updates, nil
}

func (p *plugin) PostUpdateContainer(ctx context.Context, pod *api.PodSandbox, ctr *api.Container) error {
	p.logG(ctx).Infof("Updated container %s/%s/%s...", pod.GetNamespace(), pod.GetName(), ctr.GetName())
	return nil
}

func (p *plugin) StopContainer(ctx context.Context, pod *api.PodSandbox, ctr *api.Container) ([]*api.ContainerUpdate, error) {
	p.logG(ctx).Infof("Stopped container %s/%s/%s...", pod.GetNamespace(), pod.GetName(), ctr.GetName())

	//
	// This is the container (post-)stop request handler. You can update any
	// of the remaining running containers. Take a look at the functions in
	// pkg/api/update.go to see the available controls.
	//

	return []*api.ContainerUpdate{}, nil
}

func (p *plugin) RemoveContainer(ctx context.Context, pod *api.PodSandbox, ctr *api.Container) error {
	p.logG(ctx).Infof("Removed container %s/%s/%s...", pod.GetNamespace(), pod.GetName(), ctr.GetName())
	return nil
}

func (p *plugin) onClose() {
	p.logG(context.Background()).Infof("Connection to the runtime lost.")
}

func startPlugin(ctx context.Context, t *testing.T, pluginName, pluginIdx, sockPath string) (*plugin, error) {
	p := &plugin{
		logG: func(ctx context.Context) *log.Entry {
			return log.G(ctx).WithField("nri-plugin", pluginIdx+"-"+pluginName)
		},
	}
	stub, err := stub.New(p,
		stub.WithOnClose(p.onClose),
		stub.WithPluginName(pluginName),
		stub.WithPluginIdx(pluginIdx),
		stub.WithSocketPath(sockPath),
	)
	assert.Assert(t, err)
	p.stub = stub
	err = p.stub.Start(ctx)
	assert.Assert(t, err)
	return p, nil
}
