package system

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/docker/docker/integration/internal/container"
	"github.com/docker/docker/testutil/request"
	containertypes "github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/events"
	"github.com/moby/moby/api/types/filters"
	"github.com/moby/moby/api/types/mount"
	"github.com/moby/moby/api/types/volume"
	"github.com/moby/moby/client/pkg/jsonmessage"
	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
	"gotest.tools/v3/skip"
)

func TestEventsExecDie(t *testing.T) {
	skip.If(t, testEnv.DaemonInfo.OSType == "windows", "FIXME. Suspect may need to wait until container is running before exec")
	ctx := setupTest(t)
	apiClient := testEnv.APIClient()

	cID := container.Run(ctx, t, apiClient)

	id, err := apiClient.ContainerExecCreate(ctx, cID, containertypes.ExecOptions{
		Cmd: []string{"echo", "hello"},
	})
	assert.NilError(t, err)

	msg, errs := apiClient.Events(ctx, events.ListOptions{
		Filters: filters.NewArgs(
			filters.Arg("container", cID),
			filters.Arg("event", string(events.ActionExecDie)),
		),
	})

	err = apiClient.ContainerExecStart(ctx, id.ID, containertypes.ExecStartOptions{
		Detach: true,
		Tty:    false,
	})
	assert.NilError(t, err)

	select {
	case m := <-msg:
		assert.Equal(t, m.Type, events.ContainerEventType)
		assert.Equal(t, m.Actor.ID, cID)
		assert.Equal(t, m.Action, events.ActionExecDie)
		assert.Equal(t, m.Actor.Attributes["execID"], id.ID)
		assert.Equal(t, m.Actor.Attributes["exitCode"], "0")
	case err = <-errs:
		assert.NilError(t, err)
	case <-time.After(time.Second * 3):
		t.Fatal("timeout hit")
	}
}

// Test case for #18888: Events messages have been switched from generic
// `JSONMessage` to `events.Message` types. The switch does not break the
// backward compatibility so old `JSONMessage` could still be used.
// This test verifies that backward compatibility maintains.
func TestEventsBackwardsCompatible(t *testing.T) {
	skip.If(t, testEnv.DaemonInfo.OSType == "windows", "Windows doesn't support back-compat messages")
	ctx := setupTest(t)
	apiClient := testEnv.APIClient()

	since := request.DaemonTime(ctx, t, apiClient, testEnv)
	ts := strconv.FormatInt(since.Unix(), 10)

	cID := container.Create(ctx, t, apiClient)

	// In case there is no events, the API should have responded immediately (not blocking),
	// The test here makes sure the response time is less than 3 sec.
	expectedTime := time.Now().Add(3 * time.Second)
	emptyResp, emptyBody, err := request.Get(ctx, "/events")
	assert.NilError(t, err)
	defer emptyBody.Close()
	assert.Check(t, is.DeepEqual(http.StatusOK, emptyResp.StatusCode))
	assert.Check(t, time.Now().Before(expectedTime), "timeout waiting for events api to respond, should have responded immediately")

	// We also test to make sure the `events.Message` is compatible with `JSONMessage`
	q := url.Values{}
	q.Set("since", ts)
	_, body, err := request.Get(ctx, "/events?"+q.Encode())
	assert.NilError(t, err)
	defer body.Close()

	dec := json.NewDecoder(body)
	var containerCreateEvent *jsonmessage.JSONMessage
	for {
		var event jsonmessage.JSONMessage
		if err := dec.Decode(&event); err != nil {
			if err == io.EOF {
				break
			}
			assert.NilError(t, err)
		}
		if event.Status == "create" && event.ID == cID {
			containerCreateEvent = &event
			break
		}
	}

	assert.Assert(t, containerCreateEvent != nil)
	assert.Check(t, is.Equal("create", containerCreateEvent.Status))
	assert.Check(t, is.Equal(cID, containerCreateEvent.ID))
	assert.Check(t, is.Equal("busybox", containerCreateEvent.From))
}

// TestEventsVolumeCreate verifies that volume create events are only fired
// once: when creating the volume, and not when attaching to a container.
func TestEventsVolumeCreate(t *testing.T) {
	skip.If(t, testEnv.DaemonInfo.OSType == "windows", "FIXME: Windows doesn't trigger the events? Could be a race")

	ctx := setupTest(t)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	apiClient := testEnv.APIClient()

	since := request.DaemonUnixTime(ctx, t, apiClient, testEnv)
	volName := t.Name()
	getEvents := func(messages <-chan events.Message, errs <-chan error) ([]events.Message, error) {
		var evts []events.Message

		for {
			select {
			case m := <-messages:
				evts = append(evts, m)
			case err := <-errs:
				if errors.Is(err, io.EOF) {
					return evts, nil
				}
				return nil, err
			case <-time.After(time.Second * 3):
				return nil, errors.New("timeout hit")
			}
		}
	}

	_, err := apiClient.VolumeCreate(ctx, volume.CreateOptions{Name: volName})
	assert.NilError(t, err)

	filter := filters.NewArgs(
		filters.Arg("type", "volume"),
		filters.Arg("event", "create"),
		filters.Arg("volume", volName),
	)
	messages, errs := apiClient.Events(ctx, events.ListOptions{
		Since:   since,
		Until:   request.DaemonUnixTime(ctx, t, apiClient, testEnv),
		Filters: filter,
	})

	volEvents, err := getEvents(messages, errs)
	assert.NilError(t, err)
	assert.Equal(t, len(volEvents), 1, "expected volume create event when creating a volume")

	container.Create(ctx, t, apiClient, container.WithMount(mount.Mount{
		Type:   mount.TypeVolume,
		Source: volName,
		Target: "/tmp/foo",
	}))

	messages, errs = apiClient.Events(ctx, events.ListOptions{
		Since:   since,
		Until:   request.DaemonUnixTime(ctx, t, apiClient, testEnv),
		Filters: filter,
	})

	volEvents, err = getEvents(messages, errs)
	assert.NilError(t, err)
	assert.Equal(t, len(volEvents), 1, "expected volume create event to be fired only once")
}
