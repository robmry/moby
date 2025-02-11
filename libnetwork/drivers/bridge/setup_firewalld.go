//go:build linux

package bridge

import (
	"context"
	"errors"

	"github.com/docker/docker/libnetwork/iptables"
)

func (n *bridgeNetwork) setupFirewalld(config *networkConfiguration, i *bridgeInterface) error {
	d := n.driver
	d.Lock()
	driverConfig := d.config
	d.Unlock()

	// Sanity check.
	if !driverConfig.EnableIPTables && !driverConfig.EnableIP6Tables {
		return errors.New("no need to register firewalld hooks, iptables is disabled")
	}

	iptables.OnReloaded(func() { n.pktFilter.Reload(context.Background()) })
	iptables.OnReloaded(n.reapplyPerPortIptables)
	return nil
}
