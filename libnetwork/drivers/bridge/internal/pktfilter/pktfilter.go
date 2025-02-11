package pktfilter

import (
	"context"
	"net"
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
	IfName     string
	Internal   bool
	ICC        bool
	Masquerade bool
	Config4    NetworkConfigFam
	Config6    NetworkConfigFam
}

type PktFilter interface {
	Init(ctx context.Context, config Config) error
	AddNetwork(nc NetworkConfig) (Network, error)
}

type Network interface {
	AddPort(ctx context.Context, pb types.PortBinding, childHostIP net.IP) error
	DelPort(ctx context.Context, pb types.PortBinding, childHostIP net.IP) error
	Delete(ctx context.Context) error
}
