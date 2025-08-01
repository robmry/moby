// Package awslogs provides the logdriver for forwarding container logs to Amazon CloudWatch Logs
package awslogs

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/endpointcreds"
	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
	"github.com/aws/smithy-go"
	smithymiddleware "github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	"github.com/containerd/log"
	"github.com/docker/docker/daemon/internal/lazyregexp"
	"github.com/docker/docker/daemon/logger"
	"github.com/docker/docker/daemon/logger/loggerutils"
	"github.com/docker/docker/dockerversion"
	"github.com/pkg/errors"
)

const (
	name                   = "awslogs"
	regionKey              = "awslogs-region"
	endpointKey            = "awslogs-endpoint"
	regionEnvKey           = "AWS_REGION"
	logGroupKey            = "awslogs-group"
	logStreamKey           = "awslogs-stream"
	logCreateGroupKey      = "awslogs-create-group"
	logCreateStreamKey     = "awslogs-create-stream"
	tagKey                 = "tag"
	datetimeFormatKey      = "awslogs-datetime-format"
	multilinePatternKey    = "awslogs-multiline-pattern"
	credentialsEndpointKey = "awslogs-credentials-endpoint" //nolint:gosec // G101: Potential hardcoded credentials
	forceFlushIntervalKey  = "awslogs-force-flush-interval-seconds"
	maxBufferedEventsKey   = "awslogs-max-buffered-events"
	logFormatKey           = "awslogs-format"

	defaultForceFlushInterval = 5 * time.Second
	defaultMaxBufferedEvents  = 4096

	// See: http://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_PutLogEvents.html
	perEventBytes          = 26
	maximumBytesPerPut     = 1048576
	maximumLogEventsPerPut = 10000

	// See: http://docs.aws.amazon.com/AmazonCloudWatch/latest/DeveloperGuide/cloudwatch_limits.html
	// Because the events are interpreted as UTF-8 encoded Unicode, invalid UTF-8 byte sequences are replaced with the
	// Unicode replacement character (U+FFFD), which is a 3-byte sequence in UTF-8.  To compensate for that and to avoid
	// splitting valid UTF-8 characters into invalid byte sequences, we calculate the length of each event assuming that
	// this replacement happens.
	maximumBytesPerEvent = 262144 - perEventBytes

	credentialsEndpoint = "http://169.254.170.2" //nolint:gosec // G101: Potential hardcoded credentials

	// See: https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch_Embedded_Metric_Format_Specification.html
	logsFormatHeader = "x-amzn-logs-format"
	jsonEmfLogFormat = "json/emf"
)

type logStream struct {
	logStreamName      string
	logGroupName       string
	logCreateGroup     bool
	logCreateStream    bool
	forceFlushInterval time.Duration
	multilinePattern   *regexp.Regexp
	client             api

	messages *loggerutils.MessageQueue
	closed   atomic.Bool

	sequenceToken *string
}

type logStreamConfig struct {
	logStreamName      string
	logGroupName       string
	logCreateGroup     bool
	logCreateStream    bool
	forceFlushInterval time.Duration
	maxBufferedEvents  int
	multilinePattern   *regexp.Regexp
}

var _ logger.SizedLogger = &logStream{}

type api interface {
	CreateLogGroup(context.Context, *cloudwatchlogs.CreateLogGroupInput, ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.CreateLogGroupOutput, error)
	CreateLogStream(context.Context, *cloudwatchlogs.CreateLogStreamInput, ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.CreateLogStreamOutput, error)
	PutLogEvents(context.Context, *cloudwatchlogs.PutLogEventsInput, ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.PutLogEventsOutput, error)
}

type regionFinder interface {
	GetRegion(context.Context, *imds.GetRegionInput, ...func(*imds.Options)) (*imds.GetRegionOutput, error)
}

type wrappedEvent struct {
	inputLogEvent types.InputLogEvent
	insertOrder   int
}
type byTimestamp []wrappedEvent

// init registers the awslogs driver
func init() {
	if err := logger.RegisterLogDriver(name, New); err != nil {
		panic(err)
	}
	if err := logger.RegisterLogOptValidator(name, ValidateLogOpt); err != nil {
		panic(err)
	}
}

// eventBatch holds the events that are batched for submission and the
// associated data about it.
//
// Warning: this type is not threadsafe and must not be used
// concurrently. This type is expected to be consumed in a single go
// routine and never concurrently.
type eventBatch struct {
	batch []wrappedEvent
	bytes int
}

// New creates an awslogs logger using the configuration passed in on the
// context.  Supported context configuration variables are awslogs-region,
// awslogs-endpoint, awslogs-group, awslogs-stream, awslogs-create-group,
// awslogs-multiline-pattern and awslogs-datetime-format.
// When available, configuration is also taken from environment variables
// AWS_REGION, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, the shared credentials
// file (~/.aws/credentials), and the EC2 Instance Metadata Service.
func New(info logger.Info) (logger.Logger, error) {
	containerStreamConfig, err := newStreamConfig(info)
	if err != nil {
		return nil, err
	}
	client, err := newAWSLogsClient(info)
	if err != nil {
		return nil, err
	}

	logNonBlocking := info.Config["mode"] == "non-blocking"

	containerStream := &logStream{
		logStreamName:      containerStreamConfig.logStreamName,
		logGroupName:       containerStreamConfig.logGroupName,
		logCreateGroup:     containerStreamConfig.logCreateGroup,
		logCreateStream:    containerStreamConfig.logCreateStream,
		forceFlushInterval: containerStreamConfig.forceFlushInterval,
		multilinePattern:   containerStreamConfig.multilinePattern,
		client:             client,
		messages:           loggerutils.NewMessageQueue(containerStreamConfig.maxBufferedEvents),
	}

	creationDone := make(chan bool)
	if logNonBlocking {
		const maxBackoff = 32
		go func() {
			backoff := 1
			// We're done when the logger is closed
			for !containerStream.closed.Load() {
				if err := containerStream.create(); err == nil {
					break
				}

				time.Sleep(time.Duration(backoff) * time.Second)
				if backoff < maxBackoff {
					backoff *= 2
				}
				log.G(context.TODO()).WithFields(log.Fields{
					"error":          err,
					"container-id":   info.ContainerID,
					"container-name": info.ContainerName,
				}).Error("Error while trying to initialize awslogs. Retrying in: ", backoff, " seconds")
			}
			close(creationDone)
		}()
	} else {
		if err = containerStream.create(); err != nil {
			return nil, err
		}
		close(creationDone)
	}
	go containerStream.collectBatch(creationDone)

	return containerStream, nil
}

// Parses most of the awslogs- options and prepares a config object to be used for newing the actual stream
// It has been formed out to ease Utest of the New above
func newStreamConfig(info logger.Info) (*logStreamConfig, error) {
	logGroupName := info.Config[logGroupKey]
	logStreamName, err := loggerutils.ParseLogTag(info, "{{.FullID}}")
	if err != nil {
		return nil, err
	}
	logCreateGroup := false
	if info.Config[logCreateGroupKey] != "" {
		logCreateGroup, err = strconv.ParseBool(info.Config[logCreateGroupKey])
		if err != nil {
			return nil, err
		}
	}

	forceFlushInterval := defaultForceFlushInterval
	if info.Config[forceFlushIntervalKey] != "" {
		forceFlushIntervalAsInt, err := strconv.Atoi(info.Config[forceFlushIntervalKey])
		if err != nil {
			return nil, err
		}
		forceFlushInterval = time.Duration(forceFlushIntervalAsInt) * time.Second
	}

	maxBufferedEvents := int(defaultMaxBufferedEvents)
	if info.Config[maxBufferedEventsKey] != "" {
		maxBufferedEvents, err = strconv.Atoi(info.Config[maxBufferedEventsKey])
		if err != nil {
			return nil, err
		}
	}

	if info.Config[logStreamKey] != "" {
		logStreamName = info.Config[logStreamKey]
	}
	logCreateStream := true
	if info.Config[logCreateStreamKey] != "" {
		logCreateStream, err = strconv.ParseBool(info.Config[logCreateStreamKey])
		if err != nil {
			return nil, err
		}
	}

	multilinePattern, err := parseMultilineOptions(info)
	if err != nil {
		return nil, err
	}

	containerStreamConfig := &logStreamConfig{
		logStreamName:      logStreamName,
		logGroupName:       logGroupName,
		logCreateGroup:     logCreateGroup,
		logCreateStream:    logCreateStream,
		forceFlushInterval: forceFlushInterval,
		maxBufferedEvents:  maxBufferedEvents,
		multilinePattern:   multilinePattern,
	}

	return containerStreamConfig, nil
}

// formatSequences matches each strftime format sequence.
var formatSequences = lazyregexp.New("%.")

// Parses awslogs-multiline-pattern and awslogs-datetime-format options
// If awslogs-datetime-format is present, convert the format from strftime
// to regexp and return.
// If awslogs-multiline-pattern is present, compile regexp and return
func parseMultilineOptions(info logger.Info) (*regexp.Regexp, error) {
	dateTimeFormat := info.Config[datetimeFormatKey]
	multilinePattern := info.Config[multilinePatternKey]
	// strftime input is parsed into a regular expression
	if dateTimeFormat != "" {
		// match each strftime format sequence and ReplaceAllStringFunc
		// looks up each format sequence in the conversion table strftimeToRegex
		// to replace with a defined regular expression
		multilinePattern = formatSequences.ReplaceAllStringFunc(dateTimeFormat, func(s string) string {
			return strftimeToRegex[s]
		})
	}
	if multilinePattern != "" {
		multilinePatternRe, err := regexp.Compile(multilinePattern)
		if err != nil {
			return nil, errors.Wrapf(err, "awslogs could not parse multiline pattern key %q", multilinePatternRe)
		}
		return multilinePatternRe, nil
	}
	return nil, nil
}

// Maps strftime format strings to regex
var strftimeToRegex = map[string]string{
	/*weekdayShort          */ `%a`: `(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)`,
	/*weekdayFull           */ `%A`: `(?:Monday|Tuesday|Wednesday|Thursday|Friday|Saturday|Sunday)`,
	/*weekdayZeroIndex      */ `%w`: `[0-6]`,
	/*dayZeroPadded         */ `%d`: `(?:0[1-9]|[1,2][0-9]|3[0,1])`,
	/*monthShort            */ `%b`: `(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)`,
	/*monthFull             */ `%B`: `(?:January|February|March|April|May|June|July|August|September|October|November|December)`,
	/*monthZeroPadded       */ `%m`: `(?:0[1-9]|1[0-2])`,
	/*yearCentury           */ `%Y`: `\d{4}`,
	/*yearZeroPadded        */ `%y`: `\d{2}`,
	/*hour24ZeroPadded      */ `%H`: `(?:[0,1][0-9]|2[0-3])`,
	/*hour12ZeroPadded      */ `%I`: `(?:0[0-9]|1[0-2])`,
	/*AM or PM              */ `%p`: "[A,P]M",
	/*minuteZeroPadded      */ `%M`: `[0-5][0-9]`,
	/*secondZeroPadded      */ `%S`: `[0-5][0-9]`,
	/*microsecondZeroPadded */ `%f`: `\d{6}`,
	/*utcOffset             */ `%z`: `[+-]\d{4}`,
	/*tzName                */ `%Z`: `[A-Z]{1,4}T`,
	/*dayOfYearZeroPadded   */ `%j`: `(?:0[0-9][1-9]|[1,2][0-9][0-9]|3[0-5][0-9]|36[0-6])`,
	/*milliseconds          */ `%L`: `\.\d{3}`,
}

// newRegionFinder is a variable such that the implementation
// can be swapped out for unit tests.
var newRegionFinder = func(ctx context.Context) (regionFinder, error) {
	cfg, err := config.LoadDefaultConfig(ctx) // default config, because we don't yet know the region
	if err != nil {
		return nil, err
	}

	client := imds.NewFromConfig(cfg)
	return client, nil
}

// newSDKEndpoint is a variable such that the implementation
// can be swapped out for unit tests.
var newSDKEndpoint = credentialsEndpoint

// newAWSLogsClient creates the service client for Amazon CloudWatch Logs.
// Customizations to the default client from the SDK include a Docker-specific
// User-Agent string and automatic region detection using the EC2 Instance
// Metadata Service when region is otherwise unspecified.
func newAWSLogsClient(info logger.Info, configOpts ...func(*config.LoadOptions) error) (*cloudwatchlogs.Client, error) {
	ctx := context.TODO()
	var region, endpoint *string
	if os.Getenv(regionEnvKey) != "" {
		region = aws.String(os.Getenv(regionEnvKey))
	}
	if info.Config[regionKey] != "" {
		region = aws.String(info.Config[regionKey])
	}
	if info.Config[endpointKey] != "" {
		endpoint = aws.String(info.Config[endpointKey])
	}
	if region == nil || *region == "" {
		log.G(ctx).Info("Trying to get region from IMDS")
		regFinder, err := newRegionFinder(context.TODO())
		if err != nil {
			log.G(ctx).WithError(err).Error("could not create regionFinder")
			return nil, errors.Wrap(err, "could not create regionFinder")
		}

		r, err := regFinder.GetRegion(context.TODO(), &imds.GetRegionInput{})
		if err != nil {
			log.G(ctx).WithError(err).Error("Could not get region from IMDS, environment, or log option")
			return nil, errors.Wrap(err, "cannot determine region for awslogs driver")
		}
		region = &r.Region
	}

	configOpts = append(configOpts, config.WithRegion(*region))

	if uri, ok := info.Config[credentialsEndpointKey]; ok {
		log.G(ctx).Debugf("Trying to get credentials from awslogs-credentials-endpoint")

		endpoint := fmt.Sprintf("%s%s", newSDKEndpoint, uri)
		configOpts = append(configOpts, config.WithCredentialsProvider(endpointcreds.New(endpoint)))
	}

	cfg, err := config.LoadDefaultConfig(context.TODO(), configOpts...)
	if err != nil {
		log.G(ctx).WithError(err).Error("Could not initialize AWS SDK config")
		return nil, errors.Wrap(err, "could not initialize AWS SDK config")
	}

	log.G(ctx).WithFields(log.Fields{
		"region": *region,
	}).Debug("Created awslogs client")

	var clientOpts []func(*cloudwatchlogs.Options)

	if info.Config[logFormatKey] != "" {
		logFormatMiddleware := smithymiddleware.BuildMiddlewareFunc("logFormat", func(
			ctx context.Context, in smithymiddleware.BuildInput, next smithymiddleware.BuildHandler,
		) (
			out smithymiddleware.BuildOutput, metadata smithymiddleware.Metadata, err error,
		) {
			switch v := in.Request.(type) {
			case *smithyhttp.Request:
				v.Header.Add(logsFormatHeader, jsonEmfLogFormat)
			}
			return next.HandleBuild(ctx, in)
		})
		clientOpts = append(
			clientOpts,
			cloudwatchlogs.WithAPIOptions(func(stack *smithymiddleware.Stack) error {
				return stack.Build.Add(logFormatMiddleware, smithymiddleware.Before)
			}),
		)
	}

	clientOpts = append(
		clientOpts,
		cloudwatchlogs.WithAPIOptions(middleware.AddUserAgentKeyValue("Docker", dockerversion.Version)),
		func(o *cloudwatchlogs.Options) {
			o.BaseEndpoint = endpoint
		},
	)

	client := cloudwatchlogs.NewFromConfig(cfg, clientOpts...)

	return client, nil
}

// Name returns the name of the awslogs logging driver
func (l *logStream) Name() string {
	return name
}

// BufSize returns the maximum bytes CloudWatch can handle.
func (l *logStream) BufSize() int {
	return maximumBytesPerEvent
}

var errClosed = errors.New("awslogs is closed")

// Log submits messages for logging by an instance of the awslogs logging driver
func (l *logStream) Log(msg *logger.Message) error {
	// No need to check if we are closed here since the queue will be closed
	// (i.e. returns false) in this case.
	ctx := context.TODO()
	if err := l.messages.Enqueue(ctx, msg); err != nil {
		if errors.Is(err, loggerutils.ErrQueueClosed) {
			return errClosed
		}
		return err
	}
	return nil
}

// Close closes the instance of the awslogs logging driver
func (l *logStream) Close() error {
	l.closed.Store(true)
	l.messages.Close()
	return nil
}

// create creates log group and log stream for the instance of the awslogs logging driver
func (l *logStream) create() error {
	err := l.createLogStream()
	if err == nil {
		return nil
	}

	var apiErr *types.ResourceNotFoundException
	if errors.As(err, &apiErr) && l.logCreateGroup {
		if err := l.createLogGroup(); err != nil {
			return errors.Wrap(err, "failed to create Cloudwatch log group")
		}
		err = l.createLogStream()
		if err == nil {
			return nil
		}
	}
	return errors.Wrap(err, "failed to create Cloudwatch log stream")
}

// createLogGroup creates a log group for the instance of the awslogs logging driver
func (l *logStream) createLogGroup() error {
	if _, err := l.client.CreateLogGroup(context.TODO(), &cloudwatchlogs.CreateLogGroupInput{
		LogGroupName: aws.String(l.logGroupName),
	}); err != nil {
		var apiErr smithy.APIError
		if errors.As(err, &apiErr) {
			fields := log.Fields{
				"errorCode":      apiErr.ErrorCode(),
				"message":        apiErr.ErrorMessage(),
				"logGroupName":   l.logGroupName,
				"logCreateGroup": l.logCreateGroup,
			}
			if _, ok := apiErr.(*types.ResourceAlreadyExistsException); ok {
				// Allow creation to succeed
				log.G(context.TODO()).WithFields(fields).Info("Log group already exists")
				return nil
			}
			log.G(context.TODO()).WithFields(fields).Error("Failed to create log group")
		}
		return err
	}
	return nil
}

// createLogStream creates a log stream for the instance of the awslogs logging driver
func (l *logStream) createLogStream() error {
	// Directly return if we do not want to create log stream.
	if !l.logCreateStream {
		log.G(context.TODO()).WithFields(log.Fields{
			"logGroupName":    l.logGroupName,
			"logStreamName":   l.logStreamName,
			"logCreateStream": l.logCreateStream,
		}).Info("Skipping creating log stream")
		return nil
	}

	input := &cloudwatchlogs.CreateLogStreamInput{
		LogGroupName:  aws.String(l.logGroupName),
		LogStreamName: aws.String(l.logStreamName),
	}

	_, err := l.client.CreateLogStream(context.TODO(), input)
	if err != nil {
		var apiErr smithy.APIError
		if errors.As(err, &apiErr) {
			fields := log.Fields{
				"errorCode":     apiErr.ErrorCode(),
				"message":       apiErr.ErrorMessage(),
				"logGroupName":  l.logGroupName,
				"logStreamName": l.logStreamName,
			}
			if _, ok := apiErr.(*types.ResourceAlreadyExistsException); ok {
				// Allow creation to succeed
				log.G(context.TODO()).WithFields(fields).Info("Log stream already exists")
				return nil
			}
			log.G(context.TODO()).WithFields(fields).Error("Failed to create log stream")
		}
	}
	return err
}

// newTicker is used for time-based batching.  newTicker is a variable such
// that the implementation can be swapped out for unit tests.
var newTicker = func(freq time.Duration) *time.Ticker {
	return time.NewTicker(freq)
}

// collectBatch executes as a goroutine to perform batching of log events for
// submission to the log stream.  If the awslogs-multiline-pattern or
// awslogs-datetime-format options have been configured, multiline processing
// is enabled, where log messages are stored in an event buffer until a multiline
// pattern match is found, at which point the messages in the event buffer are
// pushed to CloudWatch logs as a single log event.  Multiline messages are processed
// according to the maximumBytesPerPut constraint, and the implementation only
// allows for messages to be buffered for a maximum of 2*l.forceFlushInterval
// seconds.  If no forceFlushInterval is specified for the log stream, then the default
// of 5 seconds will be used resulting in a maximum of 10 seconds buffer time for multiline
// messages. When events are ready to be processed for submission to CloudWatch
// Logs, the processEvents method is called.  If a multiline pattern is not
// configured, log events are submitted to the processEvents method immediately.
func (l *logStream) collectBatch(created chan bool) {
	// Wait for the logstream/group to be created
	<-created
	flushInterval := l.forceFlushInterval
	if flushInterval <= 0 {
		flushInterval = defaultForceFlushInterval
	}
	ticker := newTicker(flushInterval)
	var eventBuffer []byte
	var eventBufferTimestamp int64
	batch := newEventBatch()

	chLogs := l.messages.Receiver()
	for {
		select {
		case t := <-ticker.C:
			// If event buffer is older than batch publish frequency flush the event buffer
			if eventBufferTimestamp > 0 && len(eventBuffer) > 0 {
				eventBufferAge := t.UnixNano()/int64(time.Millisecond) - eventBufferTimestamp
				eventBufferExpired := eventBufferAge >= int64(flushInterval)/int64(time.Millisecond)
				eventBufferNegative := eventBufferAge < 0
				if eventBufferExpired || eventBufferNegative {
					l.processEvent(batch, eventBuffer, eventBufferTimestamp)
					eventBuffer = eventBuffer[:0]
				}
			}
			l.publishBatch(batch)
			batch.reset()
		case msg, more := <-chLogs:
			if !more {
				// Flush event buffer and release resources
				l.processEvent(batch, eventBuffer, eventBufferTimestamp)
				l.publishBatch(batch)
				batch.reset()
				return
			}
			if eventBufferTimestamp == 0 {
				eventBufferTimestamp = msg.Timestamp.UnixNano() / int64(time.Millisecond)
			}
			line := msg.Line
			if l.multilinePattern != nil {
				lineEffectiveLen := effectiveLen(string(line))
				if l.multilinePattern.Match(line) || effectiveLen(string(eventBuffer))+lineEffectiveLen > maximumBytesPerEvent {
					// This is a new log event or we will exceed max bytes per event
					// so flush the current eventBuffer to events and reset timestamp
					l.processEvent(batch, eventBuffer, eventBufferTimestamp)
					eventBufferTimestamp = msg.Timestamp.UnixNano() / int64(time.Millisecond)
					eventBuffer = eventBuffer[:0]
				}
				// Append newline if event is less than max event size
				if lineEffectiveLen < maximumBytesPerEvent {
					line = append(line, "\n"...)
				}
				eventBuffer = append(eventBuffer, line...)
				logger.PutMessage(msg)
			} else {
				l.processEvent(batch, line, msg.Timestamp.UnixNano()/int64(time.Millisecond))
				logger.PutMessage(msg)
			}
		}
	}
}

// processEvent processes log events that are ready for submission to CloudWatch
// logs.  Batching is performed on time- and size-bases.  Time-based batching occurs
// at the interval defined by awslogs-force-flush-interval-seconds (defaults to 5 seconds).
// Size-based batching is performed on the maximum number of events per batch
// (defined in maximumLogEventsPerPut) and the maximum number of total bytes in a
// batch (defined in maximumBytesPerPut).  Log messages are split by the maximum
// bytes per event (defined in maximumBytesPerEvent).  There is a fixed per-event
// byte overhead (defined in perEventBytes) which is accounted for in split- and
// batch-calculations.  Because the events are interpreted as UTF-8 encoded
// Unicode, invalid UTF-8 byte sequences are replaced with the Unicode
// replacement character (U+FFFD), which is a 3-byte sequence in UTF-8.  To
// compensate for that and to avoid splitting valid UTF-8 characters into
// invalid byte sequences, we calculate the length of each event assuming that
// this replacement happens.
func (l *logStream) processEvent(batch *eventBatch, bytes []byte, timestamp int64) {
	for len(bytes) > 0 {
		// Split line length so it does not exceed the maximum
		splitOffset, lineBytes := findValidSplit(string(bytes), maximumBytesPerEvent)
		line := bytes[:splitOffset]
		event := wrappedEvent{
			inputLogEvent: types.InputLogEvent{
				Message:   aws.String(string(line)),
				Timestamp: aws.Int64(timestamp),
			},
			insertOrder: batch.count(),
		}

		added := batch.add(event, lineBytes)
		if added {
			bytes = bytes[splitOffset:]
		} else {
			l.publishBatch(batch)
			batch.reset()
		}
	}
}

// effectiveLen counts the effective number of bytes in the string, after
// UTF-8 normalization.  UTF-8 normalization includes replacing bytes that do
// not constitute valid UTF-8 encoded Unicode codepoints with the Unicode
// replacement codepoint U+FFFD (a 3-byte UTF-8 sequence, represented in Go as
// utf8.RuneError)
func effectiveLen(line string) int {
	effectiveBytes := 0
	for _, rune := range line {
		effectiveBytes += utf8.RuneLen(rune)
	}
	return effectiveBytes
}

// findValidSplit finds the byte offset to split a string without breaking valid
// Unicode codepoints given a maximum number of total bytes.  findValidSplit
// returns the byte offset for splitting a string or []byte, as well as the
// effective number of bytes if the string were normalized to replace invalid
// UTF-8 encoded bytes with the Unicode replacement character (a 3-byte UTF-8
// sequence, represented in Go as utf8.RuneError)
func findValidSplit(line string, maxBytes int) (splitOffset, effectiveBytes int) {
	for offset, char := range line {
		if effectiveBytes+utf8.RuneLen(char) > maxBytes {
			return offset, effectiveBytes
		}
		effectiveBytes += utf8.RuneLen(char)
	}
	return len(line), effectiveBytes
}

// publishBatch calls PutLogEvents for a given set of InputLogEvents,
// accounting for sequencing requirements (each request must reference the
// sequence token returned by the previous request).
func (l *logStream) publishBatch(batch *eventBatch) {
	if batch.isEmpty() {
		return
	}
	cwEvents := unwrapEvents(batch.events())

	nextSequenceToken, err := l.putLogEvents(cwEvents, l.sequenceToken)
	if err != nil {
		if apiErr := (*types.DataAlreadyAcceptedException)(nil); errors.As(err, &apiErr) {
			// already submitted, just grab the correct sequence token
			nextSequenceToken = apiErr.ExpectedSequenceToken
			log.G(context.TODO()).WithFields(log.Fields{
				"errorCode":     apiErr.ErrorCode(),
				"message":       apiErr.ErrorMessage(),
				"logGroupName":  l.logGroupName,
				"logStreamName": l.logStreamName,
			}).Info("Data already accepted, ignoring error")
			err = nil
		} else if apiErr := (*types.InvalidSequenceTokenException)(nil); errors.As(err, &apiErr) {
			nextSequenceToken, err = l.putLogEvents(cwEvents, apiErr.ExpectedSequenceToken)
		}
	}
	if err != nil {
		log.G(context.TODO()).Error(err)
	} else {
		l.sequenceToken = nextSequenceToken
	}
}

// putLogEvents wraps the PutLogEvents API
func (l *logStream) putLogEvents(events []types.InputLogEvent, sequenceToken *string) (*string, error) {
	input := &cloudwatchlogs.PutLogEventsInput{
		LogEvents:     events,
		SequenceToken: sequenceToken,
		LogGroupName:  aws.String(l.logGroupName),
		LogStreamName: aws.String(l.logStreamName),
	}
	resp, err := l.client.PutLogEvents(context.TODO(), input)
	if err != nil {
		var apiErr smithy.APIError
		if errors.As(err, &apiErr) {
			log.G(context.TODO()).WithFields(log.Fields{
				"errorCode":     apiErr.ErrorCode(),
				"message":       apiErr.ErrorMessage(),
				"logGroupName":  l.logGroupName,
				"logStreamName": l.logStreamName,
			}).Error("Failed to put log events")
		}
		return nil, err
	}
	return resp.NextSequenceToken, nil
}

// ValidateLogOpt looks for awslogs-specific log options awslogs-region, awslogs-endpoint
// awslogs-group, awslogs-stream, awslogs-create-group, awslogs-create-stream, awslogs-datetime-format,
// awslogs-multiline-pattern
func ValidateLogOpt(cfg map[string]string) error {
	for key := range cfg {
		switch key {
		case logGroupKey:
		case logStreamKey:
		case logCreateGroupKey:
		case logCreateStreamKey:
		case regionKey:
		case endpointKey:
		case tagKey:
		case datetimeFormatKey:
		case multilinePatternKey:
		case credentialsEndpointKey:
		case forceFlushIntervalKey:
		case maxBufferedEventsKey:
		case logFormatKey:
		default:
			return fmt.Errorf("unknown log opt '%s' for %s log driver", key, name)
		}
	}
	if cfg[logGroupKey] == "" {
		return fmt.Errorf("must specify a value for log opt '%s'", logGroupKey)
	}
	if cfg[logCreateGroupKey] != "" {
		if _, err := strconv.ParseBool(cfg[logCreateGroupKey]); err != nil {
			return fmt.Errorf("must specify valid value for log opt '%s': %v", logCreateGroupKey, err)
		}
	}
	if cfg[logCreateStreamKey] != "" {
		if _, err := strconv.ParseBool(cfg[logCreateStreamKey]); err != nil {
			return fmt.Errorf("must specify valid value for log opt '%s': %v", logCreateStreamKey, err)
		}
	}
	if cfg[forceFlushIntervalKey] != "" {
		if value, err := strconv.Atoi(cfg[forceFlushIntervalKey]); err != nil || value <= 0 {
			return fmt.Errorf("must specify a positive integer for log opt '%s': %v", forceFlushIntervalKey, cfg[forceFlushIntervalKey])
		}
	}
	if cfg[maxBufferedEventsKey] != "" {
		if value, err := strconv.Atoi(cfg[maxBufferedEventsKey]); err != nil || value <= 0 {
			return fmt.Errorf("must specify a positive integer for log opt '%s': %v", maxBufferedEventsKey, cfg[maxBufferedEventsKey])
		}
	}
	_, datetimeFormatKeyExists := cfg[datetimeFormatKey]
	_, multilinePatternKeyExists := cfg[multilinePatternKey]
	if datetimeFormatKeyExists && multilinePatternKeyExists {
		return fmt.Errorf("you cannot configure log opt '%s' and '%s' at the same time", datetimeFormatKey, multilinePatternKey)
	}

	if cfg[logFormatKey] != "" {
		// For now, only the "json/emf" log format is supported
		if cfg[logFormatKey] != jsonEmfLogFormat {
			return fmt.Errorf("unsupported log format '%s'", cfg[logFormatKey])
		}
		if datetimeFormatKeyExists || multilinePatternKeyExists {
			return fmt.Errorf("you cannot configure log opt '%s' or '%s' when log opt '%s' is set to '%s'", datetimeFormatKey, multilinePatternKey, logFormatKey, jsonEmfLogFormat)
		}
	}

	return nil
}

// Len returns the length of a byTimestamp slice.  Len is required by the
// sort.Interface interface.
func (slice byTimestamp) Len() int {
	return len(slice)
}

// Less compares two values in a byTimestamp slice by Timestamp.  Less is
// required by the sort.Interface interface.
func (slice byTimestamp) Less(i, j int) bool {
	iTimestamp, jTimestamp := int64(0), int64(0)
	if slice != nil && slice[i].inputLogEvent.Timestamp != nil {
		iTimestamp = *slice[i].inputLogEvent.Timestamp
	}
	if slice != nil && slice[j].inputLogEvent.Timestamp != nil {
		jTimestamp = *slice[j].inputLogEvent.Timestamp
	}
	if iTimestamp == jTimestamp {
		return slice[i].insertOrder < slice[j].insertOrder
	}
	return iTimestamp < jTimestamp
}

// Swap swaps two values in a byTimestamp slice with each other.  Swap is
// required by the sort.Interface interface.
func (slice byTimestamp) Swap(i, j int) {
	slice[i], slice[j] = slice[j], slice[i]
}

func unwrapEvents(events []wrappedEvent) []types.InputLogEvent {
	cwEvents := make([]types.InputLogEvent, len(events))
	for i, input := range events {
		cwEvents[i] = input.inputLogEvent
	}
	return cwEvents
}

func newEventBatch() *eventBatch {
	return &eventBatch{
		batch: make([]wrappedEvent, 0),
		bytes: 0,
	}
}

// events returns a slice of wrappedEvents sorted in order of their
// timestamps and then by their insertion order (see `byTimestamp`).
//
// Warning: this method is not threadsafe and must not be used
// concurrently.
func (b *eventBatch) events() []wrappedEvent {
	sort.Sort(byTimestamp(b.batch))
	return b.batch
}

// add adds an event to the batch of events accounting for the
// necessary overhead for an event to be logged. An error will be
// returned if the event cannot be added to the batch due to service
// limits.
//
// Warning: this method is not threadsafe and must not be used
// concurrently.
func (b *eventBatch) add(event wrappedEvent, size int) bool {
	addBytes := size + perEventBytes

	// verify we are still within service limits
	switch {
	case len(b.batch) >= maximumLogEventsPerPut:
		return false
	case b.bytes+addBytes > maximumBytesPerPut:
		return false
	}

	b.bytes += addBytes
	b.batch = append(b.batch, event)

	return true
}

// count is the number of batched events.  Warning: this method
// is not threadsafe and must not be used concurrently.
func (b *eventBatch) count() int {
	return len(b.batch)
}

// size is the total number of bytes that the batch represents.
//
// Warning: this method is not threadsafe and must not be used
// concurrently.
func (b *eventBatch) size() int {
	return b.bytes
}

func (b *eventBatch) isEmpty() bool {
	zeroEvents := b.count() == 0
	zeroSize := b.size() == 0
	return zeroEvents && zeroSize
}

// reset prepares the batch for reuse.
func (b *eventBatch) reset() {
	b.bytes = 0
	b.batch = b.batch[:0]
}
