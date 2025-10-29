package nri

import (
	"context"

	"github.com/containerd/log"
)

type logShim struct{}

func (nls *logShim) Debugf(ctx context.Context, format string, args ...interface{}) {
	log.G(ctx).Debugf("NRI: "+format, args...)
}

func (nls *logShim) Infof(ctx context.Context, format string, args ...interface{}) {
	log.G(ctx).Infof("NRI: "+format, args...)
}

func (nls *logShim) Warnf(ctx context.Context, format string, args ...interface{}) {
	log.G(ctx).Warnf("NRI: "+format, args...)
}

func (nls *logShim) Errorf(ctx context.Context, format string, args ...interface{}) {
	log.G(ctx).Errorf("NRI: "+format, args...)
}
