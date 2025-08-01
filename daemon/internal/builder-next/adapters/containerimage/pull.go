// FIXME(thaJeztah): remove once we are a module; the go:build directive prevents go from downgrading language version to go1.16:
//go:build go1.23

package containerimage

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/containerd/containerd/v2/core/content"
	c8dimages "github.com/containerd/containerd/v2/core/images"
	"github.com/containerd/containerd/v2/core/leases"
	"github.com/containerd/containerd/v2/core/remotes"
	"github.com/containerd/containerd/v2/core/remotes/docker"
	"github.com/containerd/containerd/v2/pkg/gc"
	c8dreference "github.com/containerd/containerd/v2/pkg/reference"
	cerrdefs "github.com/containerd/errdefs"
	"github.com/containerd/log"
	"github.com/containerd/platforms"
	"github.com/distribution/reference"
	dimages "github.com/docker/docker/daemon/images"
	"github.com/docker/docker/daemon/internal/distribution/metadata"
	"github.com/docker/docker/daemon/internal/distribution/xfer"
	"github.com/docker/docker/daemon/internal/image"
	"github.com/docker/docker/daemon/internal/layer"
	refstore "github.com/docker/docker/daemon/internal/refstore"
	"github.com/moby/buildkit/cache"
	"github.com/moby/buildkit/client"
	"github.com/moby/buildkit/client/llb/sourceresolver"
	"github.com/moby/buildkit/session"
	"github.com/moby/buildkit/solver"
	"github.com/moby/buildkit/solver/pb"
	"github.com/moby/buildkit/source"
	"github.com/moby/buildkit/source/containerimage"
	srctypes "github.com/moby/buildkit/source/types"
	"github.com/moby/buildkit/sourcepolicy"
	spb "github.com/moby/buildkit/sourcepolicy/pb"
	"github.com/moby/buildkit/util/flightcontrol"
	"github.com/moby/buildkit/util/imageutil"
	"github.com/moby/buildkit/util/leaseutil"
	"github.com/moby/buildkit/util/progress"
	"github.com/moby/buildkit/util/resolver"
	pkgprogress "github.com/moby/moby/api/pkg/progress"
	"github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/identity"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
	"golang.org/x/time/rate"
)

// SourceOpt is options for creating the image source
type SourceOpt struct {
	ContentStore    content.Store
	CacheAccessor   cache.Accessor
	ReferenceStore  refstore.Store
	DownloadManager *xfer.LayerDownloadManager
	MetadataStore   metadata.V2MetadataService
	ImageStore      image.Store
	RegistryHosts   docker.RegistryHosts
	LayerStore      layer.Store
	LeaseManager    leases.Manager
	GarbageCollect  func(ctx context.Context) (gc.Stats, error)
}

// Source is the source implementation for accessing container images
type Source struct {
	SourceOpt
	g flightcontrol.Group[*resolveRemoteResult]
}

// NewSource creates a new image source
func NewSource(opt SourceOpt) (*Source, error) {
	return &Source{SourceOpt: opt}, nil
}

// Schemes returns a list of SourceOp identifier schemes that this source
// should match.
func (is *Source) Schemes() []string {
	return []string{srctypes.DockerImageScheme}
}

// Identifier constructs an Identifier from the given scheme, ref, and attrs,
// all of which come from a SourceOp.
func (is *Source) Identifier(scheme, ref string, attrs map[string]string, platform *pb.Platform) (source.Identifier, error) {
	return is.registryIdentifier(ref, attrs, platform)
}

// Copied from github.com/moby/buildkit/source/containerimage/source.go
func (is *Source) registryIdentifier(ref string, attrs map[string]string, platform *pb.Platform) (source.Identifier, error) {
	id, err := containerimage.NewImageIdentifier(ref)
	if err != nil {
		return nil, err
	}

	if platform != nil {
		id.Platform = &ocispec.Platform{
			OS:           platform.OS,
			Architecture: platform.Architecture,
			Variant:      platform.Variant,
			OSVersion:    platform.OSVersion,
		}
		if platform.OSFeatures != nil {
			id.Platform.OSFeatures = append([]string{}, platform.OSFeatures...)
		}
	}

	for k, v := range attrs {
		switch k {
		case pb.AttrImageResolveMode:
			rm, err := resolver.ParseImageResolveMode(v)
			if err != nil {
				return nil, err
			}
			id.ResolveMode = rm
		case pb.AttrImageRecordType:
			rt, err := parseImageRecordType(v)
			if err != nil {
				return nil, err
			}
			id.RecordType = rt
		case pb.AttrImageLayerLimit:
			l, err := strconv.Atoi(v)
			if err != nil {
				return nil, errors.Wrapf(err, "invalid layer limit %s", v)
			}
			if l <= 0 {
				return nil, errors.Errorf("invalid layer limit %s", v)
			}
			id.LayerLimit = &l
		}
	}

	return id, nil
}

func parseImageRecordType(v string) (client.UsageRecordType, error) {
	switch client.UsageRecordType(v) {
	case "", client.UsageRecordTypeRegular:
		return client.UsageRecordTypeRegular, nil
	case client.UsageRecordTypeInternal:
		return client.UsageRecordTypeInternal, nil
	case client.UsageRecordTypeFrontend:
		return client.UsageRecordTypeFrontend, nil
	default:
		return "", errors.Errorf("invalid record type %s", v)
	}
}

func (is *Source) resolveLocal(refStr string) (*image.Image, error) {
	ref, err := reference.ParseNormalizedNamed(refStr)
	if err != nil {
		return nil, err
	}
	dgst, err := is.ReferenceStore.Get(ref)
	if err != nil {
		return nil, err
	}
	img, err := is.ImageStore.Get(image.ID(dgst))
	if err != nil {
		return nil, err
	}
	return img, nil
}

type resolveRemoteResult struct {
	ref  string
	dgst digest.Digest
	dt   []byte
}

func (is *Source) resolveRemote(ctx context.Context, ref string, platform *ocispec.Platform, sm *session.Manager, g session.Group) (digest.Digest, []byte, error) {
	p := platforms.DefaultSpec()
	if platform != nil {
		p = *platform
	}
	// key is used to synchronize resolutions that can happen in parallel when doing multi-stage.
	key := "getconfig::" + ref + "::" + platforms.FormatAll(p)
	res, err := is.g.Do(ctx, key, func(ctx context.Context) (*resolveRemoteResult, error) {
		res := resolver.DefaultPool.GetResolver(is.RegistryHosts, ref, "pull", sm, g)
		dgst, dt, err := imageutil.Config(ctx, ref, res, is.ContentStore, is.LeaseManager, platform)
		if err != nil {
			return nil, err
		}
		return &resolveRemoteResult{ref: ref, dgst: dgst, dt: dt}, nil
	})
	if err != nil {
		return "", nil, err
	}
	return res.dgst, res.dt, nil
}

// ResolveImageConfig returns image config for an image
func (is *Source) ResolveImageConfig(ctx context.Context, ref string, opt sourceresolver.Opt, sm *session.Manager, g session.Group) (digest.Digest, []byte, error) {
	if opt.ImageOpt == nil {
		return "", nil, fmt.Errorf("can only resolve an image: %v, opt: %v", ref, opt)
	}
	ref, err := applySourcePolicies(ctx, ref, opt.SourcePolicies)
	if err != nil {
		return "", nil, err
	}
	resolveMode, err := resolver.ParseImageResolveMode(opt.ImageOpt.ResolveMode)
	if err != nil {
		return "", nil, err
	}
	switch resolveMode {
	case resolver.ResolveModeForcePull:
		return is.resolveRemote(ctx, ref, opt.Platform, sm, g)
		// TODO: pull should fallback to local in case of failure to allow offline behavior
		// the fallback doesn't work currently
		/*
			if err == nil {
				return dgst, dt, err
			}
			// fallback to local
			dt, err = is.resolveLocal(ref)
			return "", dt, err
		*/

	case resolver.ResolveModeDefault:
		// default == prefer local, but in the future could be smarter
		fallthrough
	case resolver.ResolveModePreferLocal:
		img, err := is.resolveLocal(ref)
		if err == nil {
			if opt.Platform != nil && !platformMatches(img, opt.Platform) {
				log.G(ctx).WithField("ref", ref).Debugf("Requested build platform %s does not match local image platform %s, checking remote",
					path.Join(opt.Platform.OS, opt.Platform.Architecture, opt.Platform.Variant),
					path.Join(img.OS, img.Architecture, img.Variant),
				)
			} else {
				return "", img.RawJSON(), err
			}
		}
		// fallback to remote
		return is.resolveRemote(ctx, ref, opt.Platform, sm, g)
	}
	// should never happen
	return "", nil, fmt.Errorf("builder cannot resolve image %s: invalid mode %q", ref, opt.ImageOpt.ResolveMode)
}

// Resolve returns access to pulling for an identifier
func (is *Source) Resolve(ctx context.Context, id source.Identifier, sm *session.Manager, vtx solver.Vertex) (source.SourceInstance, error) {
	imageIdentifier, ok := id.(*containerimage.ImageIdentifier)
	if !ok {
		return nil, errors.Errorf("invalid image identifier %v", id)
	}

	platform := platforms.DefaultSpec()
	if imageIdentifier.Platform != nil {
		platform = *imageIdentifier.Platform
	}

	p := &puller{
		src: imageIdentifier,
		is:  is,
		// resolver: is.getResolver(is.RegistryHosts, imageIdentifier.Reference.String(), sm, g),
		platform: platform,
		sm:       sm,
	}
	return p, nil
}

type puller struct {
	is               *Source
	resolveLocalOnce sync.Once
	g                flightcontrol.Group[struct{}]
	src              *containerimage.ImageIdentifier
	desc             ocispec.Descriptor
	ref              string
	config           []byte
	platform         ocispec.Platform
	sm               *session.Manager
}

func (p *puller) resolver(g session.Group) remotes.Resolver {
	return resolver.DefaultPool.GetResolver(p.is.RegistryHosts, p.src.Reference.String(), "pull", p.sm, g)
}

func (p *puller) mainManifestKey(platform ocispec.Platform) (digest.Digest, error) {
	dt, err := json.Marshal(struct {
		Digest  digest.Digest
		OS      string
		Arch    string
		Variant string `json:",omitempty"`
	}{
		Digest:  p.desc.Digest,
		OS:      platform.OS,
		Arch:    platform.Architecture,
		Variant: platform.Variant,
	})
	if err != nil {
		return "", err
	}
	return digest.FromBytes(dt), nil
}

func (p *puller) resolveLocal() {
	p.resolveLocalOnce.Do(func() {
		dgst := p.src.Reference.Digest()
		if dgst != "" {
			info, err := p.is.ContentStore.Info(context.TODO(), dgst)
			if err == nil {
				p.ref = p.src.Reference.String()
				desc := ocispec.Descriptor{
					Size:   info.Size,
					Digest: dgst,
				}
				ra, err := p.is.ContentStore.ReaderAt(context.TODO(), desc)
				if err == nil {
					mt, err := imageutil.DetectManifestMediaType(ra)
					if err == nil {
						desc.MediaType = mt
						p.desc = desc
					}
				}
			}
		}

		if p.src.ResolveMode == resolver.ResolveModeDefault || p.src.ResolveMode == resolver.ResolveModePreferLocal {
			ref := p.src.Reference.String()
			img, err := p.is.resolveLocal(ref)
			if err == nil {
				if !platformMatches(img, &p.platform) {
					log.G(context.TODO()).WithField("ref", ref).Debugf("Requested build platform %s does not match local image platform %s, not resolving",
						path.Join(p.platform.OS, p.platform.Architecture, p.platform.Variant),
						path.Join(img.OS, img.Architecture, img.Variant),
					)
				} else {
					p.config = img.RawJSON()
				}
			}
		}
	})
}

func (p *puller) resolve(ctx context.Context, g session.Group) error {
	_, err := p.g.Do(ctx, "", func(ctx context.Context) (_ struct{}, retErr error) {
		resolveProgressDone := oneOffProgress(ctx, "resolve "+p.src.Reference.String())
		defer func() {
			_ = resolveProgressDone(retErr)
		}()

		ref, err := reference.ParseNormalizedNamed(p.src.Reference.String())
		if err != nil {
			return struct{}{}, err
		}

		if p.desc.Digest == "" && p.config == nil {
			origRef, desc, err := p.resolver(g).Resolve(ctx, ref.String())
			if err != nil {
				return struct{}{}, err
			}

			p.desc = desc
			p.ref = origRef
		}

		// Schema 1 manifests cannot be resolved to an image config
		// since the conversion must take place after all the content
		// has been read.
		// It may be possible to have a mapping between schema 1 manifests
		// and the schema 2 manifests they are converted to.
		if p.config == nil && p.desc.MediaType != c8dimages.MediaTypeDockerSchema1Manifest {
			refWithDigest, err := reference.WithDigest(ref, p.desc.Digest)
			if err != nil {
				return struct{}{}, err
			}
			_, dt, err := p.is.ResolveImageConfig(ctx, refWithDigest.String(), sourceresolver.Opt{
				Platform: &p.platform,
				ImageOpt: &sourceresolver.ResolveImageOpt{
					ResolveMode: p.src.ResolveMode.String(),
				},
			}, p.sm, g)
			if err != nil {
				return struct{}{}, err
			}

			p.ref = refWithDigest.String()
			p.config = dt
		}
		return struct{}{}, nil
	})
	return err
}

func (p *puller) CacheKey(ctx context.Context, g session.Group, index int) (string, string, solver.CacheOpts, bool, error) {
	p.resolveLocal()

	if p.desc.Digest != "" && index == 0 {
		dgst, err := p.mainManifestKey(p.platform)
		if err != nil {
			return "", "", nil, false, err
		}
		return dgst.String(), p.desc.Digest.String(), nil, false, nil
	}

	if p.config != nil {
		k := cacheKeyFromConfig(p.config).String()
		if k == "" {
			return digest.FromBytes(p.config).String(), digest.FromBytes(p.config).String(), nil, true, nil
		}
		return k, k, nil, true, nil
	}

	if err := p.resolve(ctx, g); err != nil {
		return "", "", nil, false, err
	}

	if p.desc.Digest != "" && index == 0 {
		dgst, err := p.mainManifestKey(p.platform)
		if err != nil {
			return "", "", nil, false, err
		}
		return dgst.String(), p.desc.Digest.String(), nil, false, nil
	}

	if len(p.config) == 0 && p.desc.MediaType != c8dimages.MediaTypeDockerSchema1Manifest {
		return "", "", nil, false, errors.Errorf("invalid empty config file resolved for %s", p.src.Reference.String())
	}

	k := cacheKeyFromConfig(p.config).String()
	if k == "" || p.desc.MediaType == c8dimages.MediaTypeDockerSchema1Manifest {
		dgst, err := p.mainManifestKey(p.platform)
		if err != nil {
			return "", "", nil, false, err
		}
		return dgst.String(), p.desc.Digest.String(), nil, true, nil
	}

	return k, k, nil, true, nil
}

func (p *puller) getRef(ctx context.Context, diffIDs []layer.DiffID, opts ...cache.RefOption) (cache.ImmutableRef, error) {
	var parent cache.ImmutableRef
	if len(diffIDs) > 1 {
		var err error
		parent, err = p.getRef(ctx, diffIDs[:len(diffIDs)-1], opts...)
		if err != nil {
			return nil, err
		}
		defer parent.Release(context.TODO())
	}
	return p.is.CacheAccessor.GetByBlob(ctx, ocispec.Descriptor{
		Annotations: map[string]string{
			"containerd.io/uncompressed": diffIDs[len(diffIDs)-1].String(),
		},
	}, parent, opts...)
}

func (p *puller) Snapshot(ctx context.Context, g session.Group) (cache.ImmutableRef, error) {
	p.resolveLocal()
	if len(p.config) == 0 {
		if err := p.resolve(ctx, g); err != nil {
			return nil, err
		}
	}

	if p.config != nil {
		img, err := p.is.ImageStore.Get(image.ID(digest.FromBytes(p.config)))
		if err == nil {
			if len(img.RootFS.DiffIDs) == 0 {
				return nil, nil
			}
			l, err := p.is.LayerStore.Get(img.RootFS.ChainID())
			if err == nil {
				layer.ReleaseAndLog(p.is.LayerStore, l)
				ref, err := p.getRef(ctx, img.RootFS.DiffIDs, cache.WithDescription(fmt.Sprintf("from local %s", p.ref)))
				if err != nil {
					return nil, err
				}
				return ref, nil
			}
		}
	}

	ongoing := newJobs(p.ref)

	ctx, done, err := leaseutil.WithLease(ctx, p.is.LeaseManager, leases.WithExpiration(5*time.Minute), leaseutil.MakeTemporary)
	if err != nil {
		return nil, err
	}
	defer func() {
		done(context.TODO())
		if p.is.GarbageCollect != nil {
			go p.is.GarbageCollect(context.TODO())
		}
	}()

	pctx, stopProgress := context.WithCancel(ctx)

	pw, _, ctx := progress.NewFromContext(ctx)
	defer pw.Close()

	progressDone := make(chan struct{})
	go func() {
		showProgress(pctx, ongoing, p.is.ContentStore, pw)
		close(progressDone)
	}()
	defer func() {
		<-progressDone
	}()

	fetcher, err := p.resolver(g).Fetcher(ctx, p.ref)
	if err != nil {
		stopProgress()
		return nil, err
	}

	platform := platforms.Only(p.platform)

	var nonLayers []digest.Digest

	var handlers []c8dimages.Handler
	if p.desc.MediaType == c8dimages.MediaTypeDockerSchema1Manifest {
		stopProgress()
		// similar to [github.com/docker/docker/distribution/DeprecatedSchema1ImageError]
		errMsg := "support for Docker Image Format v1 and Docker Image manifest version 2, schema 1 has been removed in Docker Engine v28.2. " +
			"More information at https://docs.docker.com/go/deprecated-image-specs/"
		return nil, cerrdefs.ErrInvalidArgument.WithMessage(errMsg)
		// TODO: Optimize to do dispatch and integrate pulling with download manager,
		// leverage existing blob mapping and layer storage
	} else {
		// TODO: need a wrapper snapshot interface that combines content
		// and snapshots as 1) buildkit shouldn't have a dependency on contentstore
		// or 2) cachemanager should manage the contentstore
		handlers = append(handlers, c8dimages.HandlerFunc(func(ctx context.Context, desc ocispec.Descriptor) ([]ocispec.Descriptor, error) {
			switch desc.MediaType {
			case c8dimages.MediaTypeDockerSchema2Manifest, ocispec.MediaTypeImageManifest,
				c8dimages.MediaTypeDockerSchema2ManifestList, ocispec.MediaTypeImageIndex,
				c8dimages.MediaTypeDockerSchema2Config, ocispec.MediaTypeImageConfig:
				nonLayers = append(nonLayers, desc.Digest)
			default:
				return nil, c8dimages.ErrSkipDesc
			}
			ongoing.add(desc)
			return nil, nil
		}))

		// Get all the children for a descriptor
		childrenHandler := c8dimages.ChildrenHandler(p.is.ContentStore)
		// Filter the children by the platform
		childrenHandler = c8dimages.FilterPlatforms(childrenHandler, platform)
		// Limit manifests pulled to the best match in an index
		childrenHandler = c8dimages.LimitManifests(childrenHandler, platform, 1)

		handlers = append(handlers,
			remotes.FetchHandler(p.is.ContentStore, fetcher),
			childrenHandler,
		)
	}

	if err := c8dimages.Dispatch(ctx, c8dimages.Handlers(handlers...), nil, p.desc); err != nil {
		stopProgress()
		return nil, err
	}
	defer stopProgress()

	mfst, err := c8dimages.Manifest(ctx, p.is.ContentStore, p.desc, platform)
	if err != nil {
		return nil, err
	}

	config, err := c8dimages.Config(ctx, p.is.ContentStore, p.desc, platform)
	if err != nil {
		return nil, err
	}

	dt, err := content.ReadBlob(ctx, p.is.ContentStore, config)
	if err != nil {
		return nil, err
	}

	var img ocispec.Image
	if err := json.Unmarshal(dt, &img); err != nil {
		return nil, err
	}

	if len(mfst.Layers) != len(img.RootFS.DiffIDs) {
		return nil, errors.Errorf("invalid config for manifest")
	}

	pchan := make(chan pkgprogress.Progress, 10)
	defer close(pchan)

	go func() {
		m := map[string]struct {
			st      time.Time
			limiter *rate.Limiter
		}{}
		for p := range pchan {
			if p.Action == "Extracting" {
				st, ok := m[p.ID]
				if !ok {
					st.st = time.Now()
					st.limiter = rate.NewLimiter(rate.Every(100*time.Millisecond), 1)
					m[p.ID] = st
				}
				var end *time.Time
				if p.LastUpdate || st.limiter.Allow() {
					if p.LastUpdate {
						tm := time.Now()
						end = &tm
					}
					_ = pw.Write("extracting "+p.ID, progress.Status{
						Action:    "extract",
						Started:   &st.st,
						Completed: end,
					})
				}
			}
		}
	}()

	if len(mfst.Layers) == 0 {
		return nil, nil
	}

	layers := make([]xfer.DownloadDescriptor, 0, len(mfst.Layers))

	for i, desc := range mfst.Layers {
		if err := desc.Digest.Validate(); err != nil {
			return nil, errors.Wrap(err, "layer digest could not be validated")
		}
		ongoing.add(desc)
		layers = append(layers, &layerDescriptor{
			desc:    desc,
			diffID:  img.RootFS.DiffIDs[i],
			fetcher: fetcher,
			ref:     p.src.Reference,
			is:      p.is,
		})
	}

	defer func() {
		<-progressDone
	}()

	rootFS, release, err := p.is.DownloadManager.Download(ctx, layers, pkgprogress.ChanOutput(pchan))
	stopProgress()
	if err != nil {
		return nil, err
	}

	ref, err := p.getRef(ctx, rootFS.DiffIDs, cache.WithDescription(fmt.Sprintf("pulled from %s", p.ref)))
	release()
	if err != nil {
		return nil, err
	}

	// keep manifest blobs until ref is alive for cache
	for _, nl := range nonLayers {
		if err := p.is.LeaseManager.AddResource(ctx, leases.Lease{ID: ref.ID()}, leases.Resource{
			ID:   nl.String(),
			Type: "content",
		}); err != nil {
			return nil, err
		}
	}

	// TODO: handle windows layers for cross platform builds

	if p.src.RecordType != "" && ref.GetRecordType() == "" {
		if err := ref.SetRecordType(p.src.RecordType); err != nil {
			ref.Release(context.TODO())
			return nil, err
		}
	}

	return ref, nil
}

// Fetch(ctx context.Context, desc ocispec.Descriptor) (io.ReadCloser, error)
type layerDescriptor struct {
	is      *Source
	fetcher remotes.Fetcher
	desc    ocispec.Descriptor
	diffID  layer.DiffID
	ref     c8dreference.Spec
}

func (ld *layerDescriptor) Key() string {
	return "v2:" + ld.desc.Digest.String()
}

func (ld *layerDescriptor) ID() string {
	return ld.desc.Digest.String()
}

func (ld *layerDescriptor) DiffID() (layer.DiffID, error) {
	return ld.diffID, nil
}

func (ld *layerDescriptor) Download(ctx context.Context, progressOutput pkgprogress.Output) (io.ReadCloser, int64, error) {
	rc, err := ld.fetcher.Fetch(ctx, ld.desc)
	if err != nil {
		return nil, 0, err
	}
	defer rc.Close()

	refKey := remotes.MakeRefKey(ctx, ld.desc)

	ld.is.ContentStore.Abort(ctx, refKey)

	if err := content.WriteBlob(ctx, ld.is.ContentStore, refKey, rc, ld.desc); err != nil {
		ld.is.ContentStore.Abort(ctx, refKey)
		return nil, 0, err
	}

	ra, err := ld.is.ContentStore.ReaderAt(ctx, ld.desc)
	if err != nil {
		return nil, 0, err
	}

	return io.NopCloser(content.NewReader(ra)), ld.desc.Size, nil
}

func (ld *layerDescriptor) Close() {
	// ld.is.ContentStore.Delete(context.TODO(), ld.desc.Digest))
}

func (ld *layerDescriptor) Registered(diffID layer.DiffID) {
	// Cache mapping from this layer's DiffID to the blobsum
	ld.is.MetadataStore.Add(diffID, metadata.V2Metadata{Digest: ld.desc.Digest, SourceRepository: ld.ref.Locator})
}

func showProgress(ctx context.Context, ongoing *jobs, cs content.Store, pw progress.Writer) {
	var (
		ticker   = time.NewTicker(100 * time.Millisecond)
		statuses = map[string]statusInfo{}
		done     bool
	)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
		case <-ctx.Done():
			done = true
		}

		resolved := "resolved"
		if !ongoing.isResolved() {
			resolved = "resolving"
		}
		statuses[ongoing.name] = statusInfo{
			Ref:    ongoing.name,
			Status: resolved,
		}

		actives := make(map[string]statusInfo)

		if !done {
			active, err := cs.ListStatuses(ctx)
			if err != nil {
				// log.G(ctx).WithError(err).Error("active check failed")
				continue
			}
			// update status of active entries!
			for _, active := range active {
				actives[active.Ref] = statusInfo{
					Ref:       active.Ref,
					Status:    "downloading",
					Offset:    active.Offset,
					Total:     active.Total,
					StartedAt: active.StartedAt,
					UpdatedAt: active.UpdatedAt,
				}
			}
		}

		// now, update the items in jobs that are not in active
		for _, j := range ongoing.jobs() {
			refKey := remotes.MakeRefKey(ctx, j.Descriptor)
			if a, ok := actives[refKey]; ok {
				started := j.started
				_ = pw.Write(j.Digest.String(), progress.Status{
					Action:  a.Status,
					Total:   int(a.Total),
					Current: int(a.Offset),
					Started: &started,
				})
				continue
			}

			if !j.done {
				info, err := cs.Info(context.TODO(), j.Digest)
				if err != nil {
					if cerrdefs.IsNotFound(err) {
						// _ = pw.Write(j.Digest.String(), progress.Status{
						// 	Action: "waiting",
						// })
						continue
					}
				} else {
					j.done = true
				}

				if done || j.done {
					started := j.started
					createdAt := info.CreatedAt
					_ = pw.Write(j.Digest.String(), progress.Status{
						Action:    "done",
						Current:   int(info.Size),
						Total:     int(info.Size),
						Completed: &createdAt,
						Started:   &started,
					})
				}
			}
		}
		if done {
			return
		}
	}
}

// jobs provides a way of identifying the download keys for a particular task
// encountering during the pull walk.
//
// This is very minimal and will probably be replaced with something more
// featured.
type jobs struct {
	name     string
	added    map[digest.Digest]*job
	mu       sync.Mutex
	resolved bool
}

type job struct {
	ocispec.Descriptor
	done    bool
	started time.Time
}

func newJobs(name string) *jobs {
	return &jobs{
		name:  name,
		added: make(map[digest.Digest]*job),
	}
}

func (j *jobs) add(desc ocispec.Descriptor) {
	j.mu.Lock()
	defer j.mu.Unlock()

	if _, ok := j.added[desc.Digest]; ok {
		return
	}
	j.added[desc.Digest] = &job{
		Descriptor: desc,
		started:    time.Now(),
	}
}

func (j *jobs) jobs() []*job {
	j.mu.Lock()
	defer j.mu.Unlock()

	descs := make([]*job, 0, len(j.added))
	for _, j := range j.added {
		descs = append(descs, j)
	}
	return descs
}

func (j *jobs) isResolved() bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.resolved
}

type statusInfo struct {
	Ref       string
	Status    string
	Offset    int64
	Total     int64
	StartedAt time.Time
	UpdatedAt time.Time
}

func oneOffProgress(ctx context.Context, id string) func(err error) error {
	pw, _, _ := progress.NewFromContext(ctx)
	s := time.Now()
	st := progress.Status{
		Started: &s,
	}
	_ = pw.Write(id, st)
	return func(err error) error {
		// TODO: set error on status
		c := time.Now()
		st.Completed = &c
		_ = pw.Write(id, st)
		_ = pw.Close()
		return err
	}
}

// cacheKeyFromConfig returns a stable digest from image config. If image config
// is a known oci image we will use chainID of layers.
func cacheKeyFromConfig(dt []byte) digest.Digest {
	var img ocispec.Image
	err := json.Unmarshal(dt, &img)
	if err != nil {
		log.G(context.TODO()).WithError(err).Errorf("failed to unmarshal image config for cache key %v", err)
		return digest.FromBytes(dt)
	}
	if img.RootFS.Type != "layers" || len(img.RootFS.DiffIDs) == 0 {
		return ""
	}
	return identity.ChainID(img.RootFS.DiffIDs)
}

func platformMatches(img *image.Image, p *ocispec.Platform) bool {
	return dimages.OnlyPlatformWithFallback(*p).Match(ocispec.Platform{
		Architecture: img.Architecture,
		OS:           img.OS,
		OSVersion:    img.OSVersion,
		OSFeatures:   img.OSFeatures,
		Variant:      img.Variant,
	})
}

func applySourcePolicies(ctx context.Context, str string, spls []*spb.Policy) (string, error) {
	ref, err := c8dreference.Parse(str)
	if err != nil {
		return "", errors.WithStack(err)
	}
	op := &pb.SourceOp{
		Identifier: srctypes.DockerImageScheme + "://" + ref.String(),
	}

	mut, err := sourcepolicy.NewEngine(spls).Evaluate(ctx, op)
	if err != nil {
		return "", errors.Wrap(err, "could not resolve image due to policy")
	}

	if mut {
		t, newRef, ok := strings.Cut(op.GetIdentifier(), "://")
		if !ok {
			return "", errors.Errorf("could not parse ref: %s", op.GetIdentifier())
		}
		if t != srctypes.DockerImageScheme {
			return "", &imageutil.ResolveToNonImageError{Ref: str, Updated: newRef}
		}
		ref, err = c8dreference.Parse(newRef)
		if err != nil {
			return "", errors.WithStack(err)
		}
	}
	return ref.String(), nil
}
