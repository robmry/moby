//go:build linux

package nftabler

import (
	"context"

	"github.com/docker/docker/libnetwork/drivers/bridge/internal/firewaller"
)

type nftabler struct {
	firewaller.Config
}

func NewNftabler(ctx context.Context, config firewaller.Config) (firewaller.Firewaller, error) {
	nft := &nftabler{Config: config}
	return nft, nil
}

func (nft *nftabler) FilterForwardDrop(ctx context.Context, ipv firewaller.IPVersion) error {
	return nil
}
