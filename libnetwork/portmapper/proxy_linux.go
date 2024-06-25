package portmapper

import (
	"fmt"
	"github.com/docker/docker/libnetwork/types"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"syscall"
	"time"
)

// StartProxy starts the proxy process at proxyPath, or instantiates a dummy proxy
// to bind the host port if proxyPath is the empty string.
func StartProxy(pb types.PortBinding,
	proxyPath string,
	listenSock *os.File,
) (stop func() error, retErr error) {
	if proxyPath == "" {
		return nil, fmt.Errorf("no path provided for userland-proxy binary")
	}
	r, w, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("proxy unable to open os.Pipe %s", err)
	}
	defer func() {
		r.Close()
		w.Close()
		listenSock.Close()
	}()

	cmd := &exec.Cmd{
		Path: proxyPath,
		Args: []string{
			proxyPath,
			"-proto", pb.Proto.String(),
			"-host-ip", pb.HostIP.String(),
			"-host-port", strconv.FormatUint(uint64(pb.HostPort), 10),
			"-container-ip", pb.IP.String(),
			"-container-port", strconv.FormatUint(uint64(pb.Port), 10),
		},
		ExtraFiles: []*os.File{w, listenSock},
		SysProcAttr: &syscall.SysProcAttr{
			Pdeathsig: syscall.SIGTERM, // send a sigterm to the proxy if the creating thread in the daemon process dies (https://go.dev/issue/27505)
		},
	}
	wait := make(chan error, 1)

	// As p.cmd.SysProcAttr.Pdeathsig is set, the signal will be sent to the
	// process when the OS thread on which p.cmd.Start() was executed dies.
	// If the thread is allowed to be released back into the goroutine
	// thread pool, the thread could get terminated at any time if a
	// goroutine gets scheduled onto it which calls runtime.LockOSThread()
	// and exits without a matching number of runtime.UnlockOSThread()
	// calls. Ensure that the thread from which Start() is called stays
	// alive until the proxy or the daemon process exits to prevent the
	// proxy from getting terminated early. See https://go.dev/issue/27505
	// for more details.
	started := make(chan error)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		err := cmd.Start()
		started <- err
		if err != nil {
			return
		}
		wait <- cmd.Wait()
	}()
	if err := <-started; err != nil {
		return nil, err
	}

	errchan := make(chan error, 1)
	go func() {
		buf := make([]byte, 2)
		r.Read(buf)

		if string(buf) != "0\n" {
			errStr, err := io.ReadAll(r)
			if err != nil {
				errchan <- fmt.Errorf("error reading exit status from userland proxy: %v", err)
				return
			}
			errchan <- fmt.Errorf("error starting userland proxy: %s", errStr)
			return
		}
		errchan <- nil
	}()

	select {
	case err := <-errchan:
		if err != nil {
			return nil, err
		}
	case <-time.After(16 * time.Second):
		return nil, fmt.Errorf("timed out starting the userland proxy")
	}

	stopFn := func() error {
		if cmd.Process == nil {
			return nil
		}
		if err := cmd.Process.Signal(os.Interrupt); err != nil {
			return err
		}
		return <-wait
	}
	return stopFn, nil
}
