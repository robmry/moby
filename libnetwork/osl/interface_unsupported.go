//go:build !linux

package osl

import (
	"time"

	"github.com/docker/docker/libnetwork/netlabel"
	"github.com/docker/docker/libnetwork/types"
)

type Interface struct{}

func ValidateAdvAddrCount(count int) error {
	return types.InvalidParameterErrorf(netlabel.AdvAddrCount + " is not supported on Windows")
}

func ValidateAdvAddrInterval(interval time.Duration) error {
	return types.InvalidParameterErrorf(netlabel.AdvAddrIntervalMs + " is not supported on Windows")
}
