// FIXME(thaJeztah): remove once we are a module; the go:build directive prevents go from downgrading language version to go1.16:
//go:build go1.23

package grpc

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/containerd/containerd/v2/defaults"
	"github.com/containerd/log"
	"github.com/docker/docker/daemon/internal/otelutil"
	"github.com/docker/docker/daemon/server/router"
	"github.com/moby/buildkit/util/grpcerrors"
	"github.com/moby/buildkit/util/stack"
	"github.com/moby/buildkit/util/tracing"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"golang.org/x/net/http2"
	"google.golang.org/grpc"
)

type grpcRouter struct {
	routes     []router.Route
	grpcServer *grpc.Server
	h2Server   *http2.Server
}

// NewRouter initializes a new grpc http router
func NewRouter(backends ...Backend) router.Router {
	tp, _ := otelutil.NewTracerProvider(context.Background(), false)
	opts := []grpc.ServerOption{
		grpc.StatsHandler(tracing.ServerStatsHandler(otelgrpc.WithTracerProvider(tp))),
		grpc.ChainUnaryInterceptor(unaryInterceptor, grpcerrors.UnaryServerInterceptor),
		grpc.StreamInterceptor(grpcerrors.StreamServerInterceptor),
		grpc.MaxRecvMsgSize(defaults.DefaultMaxRecvMsgSize),
		grpc.MaxSendMsgSize(defaults.DefaultMaxSendMsgSize),
	}

	r := &grpcRouter{
		h2Server:   &http2.Server{},
		grpcServer: grpc.NewServer(opts...),
	}
	for _, b := range backends {
		b.RegisterGRPC(r.grpcServer)
	}
	r.initRoutes()
	return r
}

// Routes returns the available routers to the session controller
func (gr *grpcRouter) Routes() []router.Route {
	return gr.routes
}

func (gr *grpcRouter) initRoutes() {
	gr.routes = []router.Route{
		router.NewPostRoute("/grpc", gr.serveGRPC),
	}
}

func unaryInterceptor(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp any, _ error) {
	// This method is used by the clients to send their traces to buildkit so they can be included
	// in the daemon trace and stored in the build history record. This method can not be traced because
	// it would cause an infinite loop.
	if strings.HasSuffix(info.FullMethod, "opentelemetry.proto.collector.trace.v1.TraceService/Export") {
		return handler(ctx, req)
	}

	resp, err := handler(ctx, req)
	if err != nil {
		log.G(ctx).WithError(err).Error(info.FullMethod)
		if log.GetLevel() >= log.DebugLevel {
			_, _ = fmt.Fprintf(os.Stderr, "%+v", stack.Formatter(grpcerrors.FromGRPC(err)))
		}
	}
	return resp, err
}
