package pktfilter

import "context"

type IPVersion int

const (
	IPv4 IPVersion = iota
	IPv6
)

type PktFilter interface {
	Init(ctx context.Context, config Config) error
	Enabled(version IPVersion) (bool, error)
}

type Config struct {
	IPv4    bool
	IPv6    bool
	Hairpin bool
}
