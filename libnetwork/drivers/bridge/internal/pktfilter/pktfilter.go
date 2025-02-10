package pktfilter

import (
	"context"
	"net/netip"

	"github.com/docker/docker/libnetwork/types"
)

type IPVersion int

const (
	IPv4 IPVersion = iota
	IPv6
)

type Config struct {
	IPv4    bool
	IPv6    bool
	Hairpin bool
}

type NetworkConfigFam struct {
	HostIP      netip.Addr
	Prefix      netip.Prefix
	Routed      bool
	Unprotected bool
}

type NetworkConfig struct {
	IfName       string
	Internal     bool
	ICC          bool
	IPMasquerade bool
	Config4      NetworkConfigFam
	Config6      NetworkConfigFam
}

type PktFilter interface {
	Init(ctx context.Context, config Config) error
	Enabled(version IPVersion) (bool, error)

	AddNetwork(nc NetworkConfig) (Network, error)
}

type Network interface {
	AddPort(ctx context.Context, pb types.PortBinding) error
	DelPort(ctx context.Context, pb types.PortBinding) error
	Delete(ctx context.Context) error
}
