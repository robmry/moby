package nftabler

import (
	"context"
	"net/netip"

	"github.com/docker/docker/libnetwork/types"
)

func (n *network) AddLink(ctx context.Context, parentIP, childIP netip.Addr, ports []types.TransportPort) error {
	panic("implement network.AddLink")
}

func (n *network) DelLink(ctx context.Context, parentIP, childIP netip.Addr, ports []types.TransportPort) {
	panic("implement network.DelLink")
}
