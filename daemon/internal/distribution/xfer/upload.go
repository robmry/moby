package xfer

import (
	"context"
	"errors"
	"time"

	"github.com/containerd/log"
	"github.com/docker/distribution"
	"github.com/docker/docker/daemon/internal/layer"
	"github.com/moby/moby/api/pkg/progress"
)

const maxUploadAttempts = 5

// LayerUploadManager provides task management and progress reporting for
// uploads.
type LayerUploadManager struct {
	tm           *transferManager
	waitDuration time.Duration
}

// SetConcurrency sets the max concurrent uploads for each push
func (lum *LayerUploadManager) SetConcurrency(concurrency int) {
	lum.tm.setConcurrency(concurrency)
}

// NewLayerUploadManager returns a new LayerUploadManager.
func NewLayerUploadManager(concurrencyLimit int, options ...func(*LayerUploadManager)) *LayerUploadManager {
	manager := LayerUploadManager{
		tm:           newTransferManager(concurrencyLimit),
		waitDuration: time.Second,
	}
	for _, option := range options {
		option(&manager)
	}
	return &manager
}

type uploadTransfer struct {
	transfer

	remoteDescriptor distribution.Descriptor
	err              error
}

// An UploadDescriptor references a layer that may need to be uploaded.
type UploadDescriptor interface {
	// Key returns the key used to deduplicate uploads.
	Key() string
	// ID returns the ID for display purposes.
	ID() string
	// DiffID should return the DiffID for this layer.
	DiffID() layer.DiffID
	// Upload is called to perform the Upload.
	Upload(ctx context.Context, progressOutput progress.Output) (distribution.Descriptor, error)
	// SetRemoteDescriptor provides the distribution.Descriptor that was
	// returned by Upload. This descriptor is not to be confused with
	// the UploadDescriptor interface, which is used for internally
	// identifying layers that are being uploaded.
	SetRemoteDescriptor(descriptor distribution.Descriptor)
}

// Upload is a blocking function which ensures the listed layers are present on
// the remote registry. It uses the string returned by the Key method to
// deduplicate uploads.
func (lum *LayerUploadManager) Upload(ctx context.Context, layers []UploadDescriptor, progressOutput progress.Output) error {
	var (
		uploads          []*uploadTransfer
		dedupDescriptors = make(map[string]*uploadTransfer)
	)

	for _, descriptor := range layers {
		progress.Update(progressOutput, descriptor.ID(), "Preparing")

		key := descriptor.Key()
		if _, present := dedupDescriptors[key]; present {
			continue
		}

		xferFunc := lum.makeUploadFunc(descriptor)
		upload, watcher := lum.tm.transfer(descriptor.Key(), xferFunc, progressOutput)
		defer upload.release(watcher)
		uploads = append(uploads, upload.(*uploadTransfer))
		dedupDescriptors[key] = upload.(*uploadTransfer)
	}

	for _, upload := range uploads {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-upload.transfer.done():
			if upload.err != nil {
				return upload.err
			}
		}
	}
	for _, l := range layers {
		l.SetRemoteDescriptor(dedupDescriptors[l.Key()].remoteDescriptor)
	}

	return nil
}

func (lum *LayerUploadManager) makeUploadFunc(descriptor UploadDescriptor) doFunc {
	return func(progressChan chan<- progress.Progress, start <-chan struct{}, inactive chan<- struct{}) transfer {
		u := &uploadTransfer{
			transfer: newTransfer(),
		}

		go func() {
			defer func() {
				close(progressChan)
			}()

			progressOutput := progress.ChanOutput(progressChan)

			select {
			case <-start:
			default:
				progress.Update(progressOutput, descriptor.ID(), "Waiting")
				<-start
			}

			retries := 0
			for {
				remoteDescriptor, err := descriptor.Upload(u.transfer.context(), progressOutput)
				if err == nil {
					u.remoteDescriptor = remoteDescriptor
					break
				}

				// If an error was returned because the context
				// was cancelled, we shouldn't retry.
				select {
				case <-u.transfer.context().Done():
					u.err = err
					return
				default:
				}

				retries++
				if _, isDNR := err.(DoNotRetry); isDNR || retries == maxUploadAttempts {
					log.G(context.TODO()).Errorf("Upload failed: %v", err)
					u.err = err
					return
				}

				log.G(context.TODO()).Errorf("Upload failed, retrying: %v", err)
				delay := retries * 5
				ticker := time.NewTicker(lum.waitDuration)

			selectLoop:
				for {
					progress.Updatef(progressOutput, descriptor.ID(), "Retrying in %d second%s", delay, (map[bool]string{true: "s"})[delay != 1])
					select {
					case <-ticker.C:
						delay--
						if delay == 0 {
							ticker.Stop()
							break selectLoop
						}
					case <-u.transfer.context().Done():
						ticker.Stop()
						u.err = errors.New("upload cancelled during retry delay")
						return
					}
				}
			}
		}()

		return u
	}
}
