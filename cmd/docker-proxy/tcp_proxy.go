package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"sync"
	"syscall"

	"github.com/pkg/errors"
)

// TCPProxy is a proxy for TCP connections. It implements the Proxy interface to
// handle TCP traffic forwarding between the frontend and backend addresses.
type TCPProxy struct {
	listener     net.Listener
	frontendAddr *net.TCPAddr
	backendAddr  *net.TCPAddr
}

// NewTCPProxy creates a new TCPProxy.
func NewTCPProxy(frontendAddr, backendAddr *net.TCPAddr) (*TCPProxy, error) {
	if err := syscall.Listen(int(listenSockFd), listenerBacklog()); err != nil {
		return nil, fmt.Errorf("failed to listen on TCP socket: %w", err)
	}
	f := os.NewFile(listenSockFd, "listen-sock")
	if f == nil {
		return nil, errors.New("failed convert TCP listen socket")
	}
	listener, err := net.FileListener(f)
	if err != nil {
		return nil, err
	}
	f.Close()
	// If the port in frontendAddr was 0 then ListenTCP will have a picked
	// a port to listen on, hence the call to Addr to get that actual port:
	return &TCPProxy{
		listener:     listener,
		frontendAddr: listener.Addr().(*net.TCPAddr),
		backendAddr:  backendAddr,
	}, nil
}

// TODO(robmry) - tidy, ack the net code
var listenerBacklogCache struct {
	sync.Once
	val int
}

func maxListenerBacklog() int {
	b, err := os.ReadFile("/proc/sys/net/core/somaxconn")
	if err != nil {
		return syscall.SOMAXCONN
	}
	n, err := strconv.ParseInt(string(b), 10, 32)
	if n == 0 || err != nil {
		return syscall.SOMAXCONN
	}
	return int(n)
}

// listenerBacklog is a caching wrapper around maxListenerBacklog.
func listenerBacklog() int {
	listenerBacklogCache.Do(func() { listenerBacklogCache.val = maxListenerBacklog() })
	return listenerBacklogCache.val
}

func (proxy *TCPProxy) clientLoop(client *net.TCPConn, quit chan bool) {
	backend, err := net.DialTCP("tcp", nil, proxy.backendAddr)
	if err != nil {
		log.Printf("Can't forward traffic to backend tcp/%v: %s\n", proxy.backendAddr, err)
		client.Close()
		return
	}

	var wg sync.WaitGroup
	broker := func(to, from *net.TCPConn) {
		io.Copy(to, from)
		from.CloseRead()
		to.CloseWrite()
		wg.Done()
	}

	wg.Add(2)
	go broker(client, backend)
	go broker(backend, client)

	finish := make(chan struct{})
	go func() {
		wg.Wait()
		close(finish)
	}()

	select {
	case <-quit:
	case <-finish:
	}
	client.Close()
	backend.Close()
	<-finish
}

// Run starts forwarding the traffic using TCP.
func (proxy *TCPProxy) Run() {
	quit := make(chan bool)
	defer close(quit)
	for {
		client, err := proxy.listener.Accept()
		if err != nil {
			log.Printf("Stopping proxy on tcp/%v for tcp/%v (%s)", proxy.frontendAddr, proxy.backendAddr, err)
			return
		}
		go proxy.clientLoop(client.(*net.TCPConn), quit)
	}
}

// Close stops forwarding the traffic.
func (proxy *TCPProxy) Close() { proxy.listener.Close() }

// FrontendAddr returns the TCP address on which the proxy is listening.
func (proxy *TCPProxy) FrontendAddr() net.Addr { return proxy.frontendAddr }

// BackendAddr returns the TCP proxied address.
func (proxy *TCPProxy) BackendAddr() net.Addr { return proxy.backendAddr }
