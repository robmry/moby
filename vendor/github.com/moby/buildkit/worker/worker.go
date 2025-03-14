package worker

import (
	"context"
	"io"

	"github.com/moby/buildkit/cache"
	"github.com/moby/buildkit/client"
	"github.com/moby/buildkit/client/llb/sourceresolver"
	"github.com/moby/buildkit/executor"
	"github.com/moby/buildkit/exporter"
	"github.com/moby/buildkit/frontend"
	"github.com/moby/buildkit/session"
	containerdsnapshot "github.com/moby/buildkit/snapshot/containerd"
	"github.com/moby/buildkit/solver"
	"github.com/moby/buildkit/solver/llbsolver/cdidevices"
	"github.com/moby/buildkit/solver/pb"
	"github.com/moby/buildkit/util/leaseutil"
	ocispecs "github.com/opencontainers/image-spec/specs-go/v1"
)

type Worker interface {
	io.Closer
	// ID needs to be unique in the cluster
	ID() string
	Labels() map[string]string
	Platforms(noCache bool) []ocispecs.Platform
	BuildkitVersion() client.BuildkitVersion

	GCPolicy() []client.PruneInfo
	LoadRef(ctx context.Context, id string, hidden bool) (cache.ImmutableRef, error)
	// ResolveOp resolves Vertex.Sys() to Op implementation.
	ResolveOp(v solver.Vertex, s frontend.FrontendLLBBridge, sm *session.Manager) (solver.Op, error)
	ResolveSourceMetadata(ctx context.Context, op *pb.SourceOp, opt sourceresolver.Opt, sm *session.Manager, g session.Group) (*sourceresolver.MetaResponse, error)
	DiskUsage(ctx context.Context, opt client.DiskUsageInfo) ([]*client.UsageInfo, error)
	Exporter(name string, sm *session.Manager) (exporter.Exporter, error)
	Prune(ctx context.Context, ch chan client.UsageInfo, opt ...client.PruneInfo) error
	FromRemote(ctx context.Context, remote *solver.Remote) (cache.ImmutableRef, error)
	PruneCacheMounts(ctx context.Context, ids map[string]bool) error
	ContentStore() *containerdsnapshot.Store
	Executor() executor.Executor
	CacheManager() cache.Manager
	LeaseManager() *leaseutil.Manager
	GarbageCollect(context.Context) error
	CDIManager() *cdidevices.Manager
}

type Infos interface {
	DefaultCacheManager() (cache.Manager, error)
	WorkerInfos() []client.WorkerInfo
}
