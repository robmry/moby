package daemon

import (
	"context"
	"strconv"
	"time"

	"github.com/containerd/log"
	"github.com/docker/docker/daemon/internal/lazyregexp"
	"github.com/docker/docker/daemon/libnetwork"
	"github.com/docker/docker/daemon/server/backend"
	"github.com/docker/docker/errdefs"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/events"
	"github.com/moby/moby/api/types/filters"
	"github.com/moby/moby/api/types/network"
	timetypes "github.com/moby/moby/api/types/time"
	"github.com/pkg/errors"
)

var (
	// errPruneRunning is returned when a prune request is received while
	// one is in progress
	errPruneRunning = errdefs.Conflict(errors.New("a prune operation is already running"))

	containersAcceptedFilters = map[string]bool{
		"label":  true,
		"label!": true,
		"until":  true,
	}

	networksAcceptedFilters = map[string]bool{
		"label":  true,
		"label!": true,
		"until":  true,
	}
)

// ContainersPrune removes unused containers
func (daemon *Daemon) ContainersPrune(ctx context.Context, pruneFilters filters.Args) (*container.PruneReport, error) {
	if !daemon.pruneRunning.CompareAndSwap(false, true) {
		return nil, errPruneRunning
	}
	defer daemon.pruneRunning.Store(false)

	rep := &container.PruneReport{}

	// make sure that only accepted filters have been received
	err := pruneFilters.Validate(containersAcceptedFilters)
	if err != nil {
		return nil, err
	}

	until, err := getUntilFromPruneFilters(pruneFilters)
	if err != nil {
		return nil, err
	}

	cfg := &daemon.config().Config
	allContainers := daemon.List()
	for _, c := range allContainers {
		select {
		case <-ctx.Done():
			log.G(ctx).Debugf("ContainersPrune operation cancelled: %#v", *rep)
			return rep, nil
		default:
		}

		if !c.IsRunning() {
			if !until.IsZero() && c.Created.After(until) {
				continue
			}
			if !matchLabels(pruneFilters, c.Config.Labels) {
				continue
			}
			cSize, _, err := daemon.imageService.GetContainerLayerSize(ctx, c.ID)
			if err != nil {
				return nil, err
			}
			// TODO: sets RmLink to true?
			err = daemon.containerRm(cfg, c.ID, &backend.ContainerRmConfig{})
			if err != nil {
				log.G(ctx).Warnf("failed to prune container %s: %v", c.ID, err)
				continue
			}
			if cSize > 0 {
				rep.SpaceReclaimed += uint64(cSize)
			}
			rep.ContainersDeleted = append(rep.ContainersDeleted, c.ID)
		}
	}
	daemon.EventsService.Log(events.ActionPrune, events.ContainerEventType, events.Actor{
		Attributes: map[string]string{"reclaimed": strconv.FormatUint(rep.SpaceReclaimed, 10)},
	})
	return rep, nil
}

// localNetworksPrune removes unused local networks
func (daemon *Daemon) localNetworksPrune(ctx context.Context, pruneFilters filters.Args) *network.PruneReport {
	rep := &network.PruneReport{}

	until, _ := getUntilFromPruneFilters(pruneFilters)

	// When the function returns true, the walk will stop.
	daemon.netController.WalkNetworks(func(nw *libnetwork.Network) bool {
		select {
		case <-ctx.Done():
			// context cancelled
			return true
		default:
		}
		if nw.ConfigOnly() {
			return false
		}
		if !until.IsZero() && nw.Created().After(until) {
			return false
		}
		if !matchLabels(pruneFilters, nw.Labels()) {
			return false
		}
		if !nw.IsPruneable() {
			return false
		}
		if len(nw.Endpoints()) > 0 {
			return false
		}
		if err := daemon.DeleteNetwork(nw.ID()); err != nil {
			log.G(ctx).Warnf("could not remove local network %s: %v", nw.Name(), err)
			return false
		}
		rep.NetworksDeleted = append(rep.NetworksDeleted, nw.Name())
		return false
	})
	return rep
}

var networkIsInUse = lazyregexp.New(`network ([[:alnum:]]+) is in use`)

// clusterNetworksPrune removes unused cluster networks
func (daemon *Daemon) clusterNetworksPrune(ctx context.Context, pruneFilters filters.Args) (*network.PruneReport, error) {
	rep := &network.PruneReport{}

	until, _ := getUntilFromPruneFilters(pruneFilters)

	cluster := daemon.GetCluster()

	if !cluster.IsManager() {
		return rep, nil
	}

	networks, err := cluster.GetNetworks(pruneFilters)
	if err != nil {
		return rep, err
	}

	for _, nw := range networks {
		select {
		case <-ctx.Done():
			return rep, nil
		default:
			if nw.Ingress {
				// Routing-mesh network removal has to be explicitly invoked by user
				continue
			}
			if !until.IsZero() && nw.Created.After(until) {
				continue
			}
			if !matchLabels(pruneFilters, nw.Labels) {
				continue
			}
			// https://github.com/docker/docker/issues/24186
			// `docker network inspect` unfortunately displays ONLY those containers that are local to that node.
			// So we try to remove it anyway and check the error
			err = cluster.RemoveNetwork(nw.ID)
			if err != nil {
				// we can safely ignore the "network .. is in use" error
				match := networkIsInUse.FindStringSubmatch(err.Error())
				if len(match) != 2 || match[1] != nw.ID {
					log.G(ctx).Warnf("could not remove cluster network %s: %v", nw.Name, err)
				}
				continue
			}
			rep.NetworksDeleted = append(rep.NetworksDeleted, nw.Name)
		}
	}
	return rep, nil
}

// NetworksPrune removes unused networks
func (daemon *Daemon) NetworksPrune(ctx context.Context, pruneFilters filters.Args) (*network.PruneReport, error) {
	if !daemon.pruneRunning.CompareAndSwap(false, true) {
		return nil, errPruneRunning
	}
	defer daemon.pruneRunning.Store(false)

	// make sure that only accepted filters have been received
	err := pruneFilters.Validate(networksAcceptedFilters)
	if err != nil {
		return nil, err
	}

	if _, err := getUntilFromPruneFilters(pruneFilters); err != nil {
		return nil, err
	}

	rep := &network.PruneReport{}
	if clusterRep, err := daemon.clusterNetworksPrune(ctx, pruneFilters); err == nil {
		rep.NetworksDeleted = append(rep.NetworksDeleted, clusterRep.NetworksDeleted...)
	}

	localRep := daemon.localNetworksPrune(ctx, pruneFilters)
	rep.NetworksDeleted = append(rep.NetworksDeleted, localRep.NetworksDeleted...)

	select {
	case <-ctx.Done():
		log.G(ctx).Debugf("NetworksPrune operation cancelled: %#v", *rep)
		return rep, nil
	default:
	}
	daemon.EventsService.Log(events.ActionPrune, events.NetworkEventType, events.Actor{
		Attributes: map[string]string{"reclaimed": "0"},
	})
	return rep, nil
}

func getUntilFromPruneFilters(pruneFilters filters.Args) (time.Time, error) {
	until := time.Time{}
	if !pruneFilters.Contains("until") {
		return until, nil
	}
	untilFilters := pruneFilters.Get("until")
	if len(untilFilters) > 1 {
		return until, errdefs.InvalidParameter(errors.New("more than one until filter specified"))
	}
	ts, err := timetypes.GetTimestamp(untilFilters[0], time.Now())
	if err != nil {
		return until, errdefs.InvalidParameter(err)
	}
	seconds, nanoseconds, err := timetypes.ParseTimestamps(ts, 0)
	if err != nil {
		return until, errdefs.InvalidParameter(err)
	}
	until = time.Unix(seconds, nanoseconds)
	return until, nil
}

func matchLabels(pruneFilters filters.Args, labels map[string]string) bool {
	if !pruneFilters.MatchKVList("label", labels) {
		return false
	}
	// By default MatchKVList will return true if field (like 'label!') does not exist
	// So we have to add additional Contains("label!") check
	if pruneFilters.Contains("label!") {
		if pruneFilters.MatchKVList("label!", labels) {
			return false
		}
	}
	return true
}
