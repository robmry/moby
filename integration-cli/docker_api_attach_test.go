package main

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/docker/docker/integration-cli/cli"
	"github.com/docker/docker/testutil"
	"github.com/docker/docker/testutil/request"
	"github.com/docker/go-connections/sockets"
	"github.com/moby/moby/api/pkg/stdcopy"
	"github.com/moby/moby/api/types"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"
	"github.com/pkg/errors"
	"golang.org/x/net/websocket"
	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
)

func (s *DockerAPISuite) TestGetContainersAttachWebsocket(c *testing.T) {
	cid := cli.DockerCmd(c, "run", "-di", "busybox", "cat").Stdout()
	cid = strings.TrimSpace(cid)

	rwc, err := request.SockConn(10*time.Second, request.DaemonHost())
	assert.NilError(c, err)

	config, err := websocket.NewConfig(
		"/containers/"+cid+"/attach/ws?stream=1&stdin=1&stdout=1&stderr=1",
		"http://localhost",
	)
	assert.NilError(c, err)

	ws, err := websocket.NewClient(config, rwc)
	assert.NilError(c, err)
	defer ws.Close()

	expected := []byte("hello")
	actual := make([]byte, len(expected))

	outChan := make(chan error, 1)
	go func() {
		_, err := io.ReadFull(ws, actual)
		outChan <- err
		close(outChan)
	}()

	inChan := make(chan error, 1)
	go func() {
		_, err := ws.Write(expected)
		inChan <- err
		close(inChan)
	}()

	select {
	case err := <-inChan:
		assert.NilError(c, err)
	case <-time.After(5 * time.Second):
		c.Fatal("Timeout writing to ws")
	}

	select {
	case err := <-outChan:
		assert.NilError(c, err)
	case <-time.After(5 * time.Second):
		c.Fatal("Timeout reading from ws")
	}

	assert.Assert(c, is.DeepEqual(actual, expected), "Websocket didn't return the expected data")
}

// regression gh14320
func (s *DockerAPISuite) TestPostContainersAttachContainerNotFound(c *testing.T) {
	ctx := testutil.GetContext(c)
	resp, _, err := request.Post(ctx, "/containers/doesnotexist/attach")
	assert.NilError(c, err)
	// connection will shutdown, err should be "persistent connection closed"
	assert.Equal(c, resp.StatusCode, http.StatusNotFound)
	content, err := request.ReadBody(resp.Body)
	assert.NilError(c, err)
	expected := "No such container: doesnotexist\r\n"
	assert.Equal(c, string(content), expected)
}

func (s *DockerAPISuite) TestGetContainersWsAttachContainerNotFound(c *testing.T) {
	ctx := testutil.GetContext(c)
	res, body, err := request.Get(ctx, "/containers/doesnotexist/attach/ws")
	assert.NilError(c, err)
	assert.Equal(c, res.StatusCode, http.StatusNotFound)
	b, err := request.ReadBody(body)
	assert.NilError(c, err)
	expected := "No such container: doesnotexist"
	assert.Assert(c, is.Contains(getErrorMessage(c, b), expected))
}

func (s *DockerAPISuite) TestPostContainersAttach(c *testing.T) {
	testRequires(c, DaemonIsLinux)

	expectSuccess := func(wc io.WriteCloser, br *bufio.Reader, stream string, tty bool) {
		defer wc.Close()
		expected := []byte("success")
		_, err := wc.Write(expected)
		assert.NilError(c, err)

		lenHeader := 0
		if !tty {
			lenHeader = 8
		}
		actual := make([]byte, len(expected)+lenHeader)
		_, err = readTimeout(br, actual, time.Second)
		assert.NilError(c, err)
		if !tty {
			fdMap := map[string]byte{
				"stdin":  0,
				"stdout": 1,
				"stderr": 2,
			}
			assert.Equal(c, actual[0], fdMap[stream])
		}
		assert.Assert(c, is.DeepEqual(actual[lenHeader:], expected), "Attach didn't return the expected data from %s", stream)
	}

	expectTimeout := func(wc io.WriteCloser, br *bufio.Reader, stream string) {
		defer wc.Close()
		_, err := wc.Write([]byte{'t'})
		assert.NilError(c, err)

		actual := make([]byte, 1)
		_, err = readTimeout(br, actual, time.Second)
		assert.Assert(c, err.Error() == "Timeout", "Read from %s is expected to timeout", stream)
	}

	// Create a container that only emits stdout.
	cid := cli.DockerCmd(c, "run", "-di", "busybox", "cat").Stdout()
	cid = strings.TrimSpace(cid)

	// Attach to the container's stdout stream.
	wc, br, err := requestHijack(http.MethodPost, "/containers/"+cid+"/attach?stream=1&stdin=1&stdout=1", nil, "text/plain", request.DaemonHost())
	assert.NilError(c, err)
	// Check if the data from stdout can be received.
	expectSuccess(wc, br, "stdout", false)

	// Attach to the container's stderr stream.
	wc, br, err = requestHijack(http.MethodPost, "/containers/"+cid+"/attach?stream=1&stdin=1&stderr=1", nil, "text/plain", request.DaemonHost())
	assert.NilError(c, err)
	// Since the container only emits stdout, attaching to stderr should return nothing.
	expectTimeout(wc, br, "stdout")

	// Test the similar functions of the stderr stream.
	cid = cli.DockerCmd(c, "run", "-di", "busybox", "/bin/sh", "-c", "cat >&2").Stdout()
	cid = strings.TrimSpace(cid)
	wc, br, err = requestHijack(http.MethodPost, "/containers/"+cid+"/attach?stream=1&stdin=1&stderr=1", nil, "text/plain", request.DaemonHost())
	assert.NilError(c, err)
	expectSuccess(wc, br, "stderr", false)
	wc, br, err = requestHijack(http.MethodPost, "/containers/"+cid+"/attach?stream=1&stdin=1&stdout=1", nil, "text/plain", request.DaemonHost())
	assert.NilError(c, err)
	expectTimeout(wc, br, "stderr")

	// Test with tty.
	cid = cli.DockerCmd(c, "run", "-dit", "busybox", "/bin/sh", "-c", "cat >&2").Stdout()
	cid = strings.TrimSpace(cid)
	// Attach to stdout only.
	wc, br, err = requestHijack(http.MethodPost, "/containers/"+cid+"/attach?stream=1&stdin=1&stdout=1", nil, "text/plain", request.DaemonHost())
	assert.NilError(c, err)
	expectSuccess(wc, br, "stdout", true)

	// Attach without stdout stream.
	wc, br, err = requestHijack(http.MethodPost, "/containers/"+cid+"/attach?stream=1&stdin=1&stderr=1", nil, "text/plain", request.DaemonHost())
	assert.NilError(c, err)
	// Nothing should be received because both the stdout and stderr of the container will be
	// sent to the client as stdout when tty is enabled.
	expectTimeout(wc, br, "stdout")

	// Test the client API
	apiClient, err := client.NewClientWithOpts(client.FromEnv)
	assert.NilError(c, err)
	defer apiClient.Close()

	cid = cli.DockerCmd(c, "run", "-di", "busybox", "/bin/sh", "-c", "echo hello; cat").Stdout()
	cid = strings.TrimSpace(cid)

	// Make sure we don't see "hello" if Logs is false
	attachOpts := container.AttachOptions{
		Stream: true,
		Stdin:  true,
		Stdout: true,
		Stderr: true,
		Logs:   false,
	}

	resp, err := apiClient.ContainerAttach(testutil.GetContext(c), cid, attachOpts)
	assert.NilError(c, err)
	mediaType, b := resp.MediaType()
	assert.Check(c, b)
	assert.Equal(c, mediaType, types.MediaTypeMultiplexedStream)
	expectSuccess(resp.Conn, resp.Reader, "stdout", false)

	// Make sure we do see "hello" if Logs is true
	attachOpts.Logs = true
	resp, err = apiClient.ContainerAttach(testutil.GetContext(c), cid, attachOpts)
	assert.NilError(c, err)

	defer resp.Conn.Close()
	assert.NilError(c, resp.Conn.SetReadDeadline(time.Now().Add(time.Second)))

	_, err = resp.Conn.Write([]byte("success"))
	assert.NilError(c, err)

	var outBuf, errBuf bytes.Buffer
	var nErr net.Error
	_, err = stdcopy.StdCopy(&outBuf, &errBuf, resp.Reader)
	if errors.As(err, &nErr) && nErr.Timeout() {
		// ignore the timeout error as it is expected
		err = nil
	}
	assert.NilError(c, err)
	assert.Equal(c, errBuf.String(), "")
	assert.Equal(c, outBuf.String(), "hello\nsuccess")
}

// requestHijack create a http request to specified host with `Upgrade` header (with method
// , contenttype, …), if receive a successful "101 Switching Protocols" response return
// a `io.WriteCloser` and `bufio.Reader`
func requestHijack(method, endpoint string, data io.Reader, ct, daemon string, modifiers ...func(*http.Request)) (io.WriteCloser, *bufio.Reader, error) {
	hostURL, err := client.ParseHostURL(daemon)
	if err != nil {
		return nil, nil, errors.Wrap(err, "parse daemon host error")
	}

	req, err := http.NewRequest(method, endpoint, data)
	if err != nil {
		return nil, nil, errors.Wrap(err, "could not create new request")
	}
	req.URL.Scheme = "http"
	req.URL.Host = hostURL.Host

	if hostURL.Scheme == "unix" || hostURL.Scheme == "npipe" {
		// Override host header for non-tcp connections.
		req.Host = client.DummyHost
	}

	for _, opt := range modifiers {
		opt(req)
	}

	if ct != "" {
		req.Header.Set("Content-Type", ct)
	}

	// must have Upgrade header
	// server api return 101 Switching Protocols
	req.Header.Set("Upgrade", "tcp")

	// new client
	// FIXME use testutil/request newHTTPClient
	transport := &http.Transport{}
	err = sockets.ConfigureTransport(transport, hostURL.Scheme, hostURL.Host)
	if err != nil {
		return nil, nil, errors.Wrap(err, "configure Transport error")
	}

	c := http.Client{
		Transport: transport,
	}

	resp, err := c.Do(req)
	if err != nil {
		return nil, nil, errors.Wrap(err, "client.Do")
	}

	if !bodyIsWritable(resp) {
		return nil, nil, errors.New("response.Body not writable")
	}

	return resp.Body.(io.WriteCloser), bufio.NewReader(resp.Body), nil
}

// bodyIsWritable check Response.Body is writable
func bodyIsWritable(r *http.Response) bool {
	_, ok := r.Body.(io.Writer)
	return ok
}

// readTimeout read from io.Reader with timeout
func readTimeout(r io.Reader, buf []byte, timeout time.Duration) (n int, err error) {
	ch := make(chan bool, 1)
	go func() {
		n, err = io.ReadFull(r, buf)
		ch <- true
	}()
	select {
	case <-ch:
		return n, err
	case <-time.After(timeout):
		return 0, errors.New("Timeout")
	}
}
