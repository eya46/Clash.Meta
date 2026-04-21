package tailscale

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/log"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
	"tailscale.com/types/views"
)

type fakeServer struct {
	client         localClient
	startErr       error
	localClientErr error
	closeErr       error
	startFn        func() error
	closeFn        func() error
	dialFn         func(ctx context.Context, network, address string) (net.Conn, error)
}

func (s *fakeServer) Start() error {
	if s.startFn != nil {
		return s.startFn()
	}
	return s.startErr
}

func (s *fakeServer) LocalClient() (localClient, error) {
	if s.localClientErr != nil {
		return nil, s.localClientErr
	}
	return s.client, nil
}

func (s *fakeServer) Close() error {
	if s.closeFn != nil {
		return s.closeFn()
	}
	return s.closeErr
}

func (s *fakeServer) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	if s.dialFn != nil {
		return s.dialFn(ctx, network, address)
	}
	return nil, errors.New("fake dial not implemented")
}

type fakeClient struct {
	editPrefsFn      func(ctx context.Context, mp *ipn.MaskedPrefs) (*ipn.Prefs, error)
	statusFn         func(ctx context.Context) (*ipnstate.Status, error)
	watchIPNBusFn    func(ctx context.Context, mask ipn.NotifyWatchOpt) (ipnBusWatcher, error)
	pingFn           func(ctx context.Context, ip netip.Addr, pingtype tailcfg.PingType) (*ipnstate.PingResult, error)
	currentDERPMapFn func(ctx context.Context) (*tailcfg.DERPMap, error)
}

func (c *fakeClient) EditPrefs(ctx context.Context, mp *ipn.MaskedPrefs) (*ipn.Prefs, error) {
	if c.editPrefsFn != nil {
		return c.editPrefsFn(ctx, mp)
	}
	return &ipn.Prefs{}, nil
}

func (c *fakeClient) Status(ctx context.Context) (*ipnstate.Status, error) {
	if c.statusFn != nil {
		return c.statusFn(ctx)
	}
	return &ipnstate.Status{BackendState: ipn.Running.String()}, nil
}

func (c *fakeClient) WatchIPNBus(ctx context.Context, mask ipn.NotifyWatchOpt) (ipnBusWatcher, error) {
	if c.watchIPNBusFn != nil {
		return c.watchIPNBusFn(ctx, mask)
	}
	return &fakeWatcher{
		nextFn: func() (ipn.Notify, error) {
			<-ctx.Done()
			return ipn.Notify{}, ctx.Err()
		},
	}, nil
}

func (c *fakeClient) Ping(ctx context.Context, ip netip.Addr, pingtype tailcfg.PingType) (*ipnstate.PingResult, error) {
	if c.pingFn != nil {
		return c.pingFn(ctx, ip, pingtype)
	}
	return &ipnstate.PingResult{}, nil
}

func (c *fakeClient) CurrentDERPMap(ctx context.Context) (*tailcfg.DERPMap, error) {
	if c.currentDERPMapFn != nil {
		return c.currentDERPMapFn(ctx)
	}
	return nil, nil
}

type fakeWatcher struct {
	nextFn  func() (ipn.Notify, error)
	closeFn func() error
}

func (w *fakeWatcher) Next() (ipn.Notify, error) {
	if w.nextFn != nil {
		return w.nextFn()
	}
	return ipn.Notify{}, io.EOF
}

func (w *fakeWatcher) Close() error {
	if w.closeFn != nil {
		return w.closeFn()
	}
	return nil
}

func newTestManager() *manager {
	return &manager{
		state: State{
			BackendState: ipn.Stopped.String(),
		},
	}
}

func restoreTestHooks(t *testing.T) {
	t.Helper()

	originalNewTSNetServer := newTSNetServer
	originalRequestTimeout := tailscaleRequestTimeout
	originalWatcherExitWait := tailscaleWatcherExitWait
	originalServerCloseWait := tailscaleServerCloseWait
	originalWatchRetryMax := tailscaleWatchRetryMax
	originalWatchRetryBackoff := tailscaleWatchRetryBackoff
	originalWatchRetryCap := tailscaleWatchRetryCap
	originalDialTimeout := tailscaleDialTimeout

	t.Cleanup(func() {
		newTSNetServer = originalNewTSNetServer
		tailscaleRequestTimeout = originalRequestTimeout
		tailscaleWatcherExitWait = originalWatcherExitWait
		tailscaleServerCloseWait = originalServerCloseWait
		tailscaleWatchRetryMax = originalWatchRetryMax
		tailscaleWatchRetryBackoff = originalWatchRetryBackoff
		tailscaleWatchRetryCap = originalWatchRetryCap
		tailscaleDialTimeout = originalDialTimeout
	})
}

func TestApplyConfigDisableEnableWithFakeServer(t *testing.T) {
	restoreTestHooks(t)
	defaultManager = newTestManager()
	t.Cleanup(func() {
		_ = Close()
	})

	var serverCount atomic.Int32

	newTSNetServer = func(config Config) tsnetServer {
		serverCount.Add(1)
		return &fakeServer{
			client: &fakeClient{
				statusFn: func(ctx context.Context) (*ipnstate.Status, error) {
					return &ipnstate.Status{
						BackendState: ipn.Running.String(),
						TailscaleIPs: []netip.Addr{netip.MustParseAddr("100.64.0.1")},
					}, nil
				},
				watchIPNBusFn: func(ctx context.Context, mask ipn.NotifyWatchOpt) (ipnBusWatcher, error) {
					return &fakeWatcher{
						nextFn: func() (ipn.Notify, error) {
							<-ctx.Done()
							return ipn.Notify{}, ctx.Err()
						},
					}, nil
				},
			},
		}
	}

	if err := ApplyConfig(Config{
		Enable:       true,
		AcceptRoutes: true,
		Dir:          t.TempDir(),
		Hostname:     "test-host-1",
	}); err != nil {
		t.Fatalf("enable tailscale: %v", err)
	}

	firstSession := defaultManager.session
	firstState := Snapshot()
	if !firstState.Enable {
		t.Fatalf("expected tailscale enabled after first apply")
	}
	if firstState.BackendState != ipn.Running.String() {
		t.Fatalf("unexpected backend state after enable: %s", firstState.BackendState)
	}

	if err := ApplyConfig(Config{Enable: false}); err != nil {
		t.Fatalf("disable tailscale: %v", err)
	}

	secondSession := defaultManager.session
	secondState := Snapshot()
	if secondState.Enable {
		t.Fatalf("expected tailscale disabled after close")
	}
	if secondState.BackendState != ipn.Stopped.String() {
		t.Fatalf("unexpected backend state after disable: %s", secondState.BackendState)
	}
	if secondSession <= firstSession {
		t.Fatalf("expected session to advance on disable: first=%d second=%d", firstSession, secondSession)
	}

	if err := ApplyConfig(Config{
		Enable:       true,
		AcceptRoutes: true,
		Dir:          t.TempDir(),
		Hostname:     "test-host-2",
	}); err != nil {
		t.Fatalf("re-enable tailscale: %v", err)
	}

	thirdSession := defaultManager.session
	thirdState := Snapshot()
	if !thirdState.Enable {
		t.Fatalf("expected tailscale enabled after restart")
	}
	if thirdState.BackendState != ipn.Running.String() {
		t.Fatalf("unexpected backend state after restart: %s", thirdState.BackendState)
	}
	if thirdSession <= secondSession {
		t.Fatalf("expected session to advance on restart: second=%d third=%d", secondSession, thirdSession)
	}
	if got := serverCount.Load(); got != 2 {
		t.Fatalf("expected 2 fake servers, got %d", got)
	}
}

func TestRefreshStatusIgnoresStaleSession(t *testing.T) {
	restoreTestHooks(t)

	m := newTestManager()
	m.session = 2
	m.config = Config{
		Enable:       true,
		AcceptRoutes: true,
	}
	m.state = State{
		Enable:       true,
		AcceptRoutes: true,
		BackendState: ipn.Starting.String(),
	}

	staleClient := &fakeClient{
		statusFn: func(ctx context.Context) (*ipnstate.Status, error) {
			return &ipnstate.Status{
				BackendState: ipn.Running.String(),
				TailscaleIPs: []netip.Addr{netip.MustParseAddr("100.64.0.10")},
			}, nil
		},
	}

	if err := m.refreshStatus(1, staleClient); err != nil {
		t.Fatalf("refresh stale session: %v", err)
	}
	if m.state.BackendState != ipn.Starting.String() {
		t.Fatalf("stale refresh should not mutate backend state, got %s", m.state.BackendState)
	}
	if len(m.state.TailscaleIPs) != 0 {
		t.Fatalf("stale refresh should not populate tailscale IPs")
	}

	currentClient := &fakeClient{
		statusFn: func(ctx context.Context) (*ipnstate.Status, error) {
			return &ipnstate.Status{
				BackendState: ipn.Running.String(),
				TailscaleIPs: []netip.Addr{netip.MustParseAddr("100.64.0.20")},
			}, nil
		},
	}

	if err := m.refreshStatus(2, currentClient); err != nil {
		t.Fatalf("refresh current session: %v", err)
	}
	if m.state.BackendState != ipn.Running.String() {
		t.Fatalf("current refresh should update backend state, got %s", m.state.BackendState)
	}
	if len(m.state.TailscaleIPs) != 1 || m.state.TailscaleIPs[0] != "100.64.0.20" {
		t.Fatalf("unexpected tailscale IPs after refresh: %+v", m.state.TailscaleIPs)
	}
}

func TestRunWatcherIgnoresStaleNotificationAfterSessionAdvance(t *testing.T) {
	restoreTestHooks(t)

	m := newTestManager()
	m.session = 1
	m.config = Config{
		Enable:       true,
		AcceptRoutes: true,
	}
	m.state = State{
		Enable:       true,
		AcceptRoutes: true,
		BackendState: ipn.Starting.String(),
	}

	var statusCalls atomic.Int32
	entered := make(chan struct{})
	release := make(chan struct{})
	running := ipn.Running
	socketDown := "socket down"
	var nextCalls atomic.Int32

	client := &fakeClient{
		watchIPNBusFn: func(ctx context.Context, mask ipn.NotifyWatchOpt) (ipnBusWatcher, error) {
			return &fakeWatcher{
				nextFn: func() (ipn.Notify, error) {
					switch nextCalls.Add(1) {
					case 1:
						close(entered)
						<-release
						return ipn.Notify{
							State:      &running,
							ErrMessage: &socketDown,
						}, nil
					default:
						return ipn.Notify{}, io.EOF
					}
				},
			}, nil
		},
		statusFn: func(ctx context.Context) (*ipnstate.Status, error) {
			statusCalls.Add(1)
			return &ipnstate.Status{BackendState: ipn.Running.String()}, nil
		},
	}

	resultCh := make(chan error, 1)
	go func() {
		resultCh <- m.runWatcher(context.Background(), 1, client)
	}()

	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("watcher did not start reading")
	}

	m.mu.Lock()
	m.session = 2
	m.state = State{
		Enable:       true,
		AcceptRoutes: true,
		BackendState: ipn.Starting.String(),
	}
	m.mu.Unlock()

	close(release)

	select {
	case err := <-resultCh:
		if !errors.Is(err, io.EOF) {
			t.Fatalf("unexpected watcher result: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("runWatcher did not exit")
	}

	if got := statusCalls.Load(); got != 0 {
		t.Fatalf("stale watcher should not refresh current session, statusCalls=%d", got)
	}

	state := m.state
	if state.BackendState != ipn.Starting.String() {
		t.Fatalf("stale watcher changed backend state: %s", state.BackendState)
	}
	if state.Error != "" {
		t.Fatalf("stale watcher set error unexpectedly: %s", state.Error)
	}
}

func TestHandleNotificationPreservesStartingOnNoState(t *testing.T) {
	m := newTestManager()
	m.session = 1
	m.state = State{
		Enable:       true,
		AcceptRoutes: true,
		BackendState: ipn.Starting.String(),
	}

	noState := ipn.NoState
	m.handleNotification(1, &ipn.Notify{State: &noState})

	if m.state.BackendState != ipn.Starting.String() {
		t.Fatalf("expected Starting to be preserved, got %s", m.state.BackendState)
	}
}

func TestEnableWaitsForPreviousServerClose(t *testing.T) {
	restoreTestHooks(t)
	defaultManager = newTestManager()
	t.Cleanup(func() {
		_ = Close()
	})

	tailscaleServerCloseWait = time.Second

	stateDir := t.TempDir()
	firstCloseStarted := make(chan struct{})
	allowFirstClose := make(chan struct{})
	secondStartCalled := make(chan struct{})

	var factoryCalls atomic.Int32
	newTSNetServer = func(config Config) tsnetServer {
		call := factoryCalls.Add(1)
		switch call {
		case 1:
			return &fakeServer{
				client: &fakeClient{
					statusFn: func(ctx context.Context) (*ipnstate.Status, error) {
						return &ipnstate.Status{BackendState: ipn.Running.String()}, nil
					},
					watchIPNBusFn: func(ctx context.Context, mask ipn.NotifyWatchOpt) (ipnBusWatcher, error) {
						return &fakeWatcher{
							nextFn: func() (ipn.Notify, error) {
								<-ctx.Done()
								return ipn.Notify{}, ctx.Err()
							},
						}, nil
					},
				},
				closeFn: func() error {
					close(firstCloseStarted)
					<-allowFirstClose
					return nil
				},
			}
		case 2:
			return &fakeServer{
				startFn: func() error {
					close(secondStartCalled)
					return nil
				},
				client: &fakeClient{
					statusFn: func(ctx context.Context) (*ipnstate.Status, error) {
						return &ipnstate.Status{BackendState: ipn.Running.String()}, nil
					},
					watchIPNBusFn: func(ctx context.Context, mask ipn.NotifyWatchOpt) (ipnBusWatcher, error) {
						return &fakeWatcher{
							nextFn: func() (ipn.Notify, error) {
								<-ctx.Done()
								return ipn.Notify{}, ctx.Err()
							},
						}, nil
					},
				},
			}
		default:
			t.Fatalf("unexpected server factory call: %d", call)
			return nil
		}
	}

	if err := ApplyConfig(Config{
		Enable:       true,
		AcceptRoutes: true,
		Dir:          stateDir,
		Hostname:     "test-host-1",
	}); err != nil {
		t.Fatalf("enable first tailscale server: %v", err)
	}

	if err := ApplyConfig(Config{Enable: false}); err != nil {
		t.Fatalf("disable tailscale: %v", err)
	}

	select {
	case <-firstCloseStarted:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("first server close did not start")
	}

	enableErrCh := make(chan error, 1)
	go func() {
		enableErrCh <- ApplyConfig(Config{
			Enable:       true,
			AcceptRoutes: true,
			Dir:          stateDir,
			Hostname:     "test-host-2",
		})
	}()

	select {
	case err := <-enableErrCh:
		t.Fatalf("second enable returned before first close completed: %v", err)
	case <-secondStartCalled:
		t.Fatal("second server started before first close completed")
	case <-time.After(100 * time.Millisecond):
	}

	close(allowFirstClose)

	select {
	case err := <-enableErrCh:
		if err != nil {
			t.Fatalf("second enable failed: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("second enable did not finish after first close completed")
	}

	select {
	case <-secondStartCalled:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("second server did not start after first close completed")
	}
}

func TestEnableFailsWhenPreviousServerCloseTimesOut(t *testing.T) {
	restoreTestHooks(t)
	defaultManager = newTestManager()
	t.Cleanup(func() {
		_ = Close()
	})

	tailscaleServerCloseWait = 50 * time.Millisecond

	stateDir := t.TempDir()
	firstCloseStarted := make(chan struct{})
	allowFirstClose := make(chan struct{})
	secondStartCalled := make(chan struct{})

	var factoryCalls atomic.Int32
	newTSNetServer = func(config Config) tsnetServer {
		call := factoryCalls.Add(1)
		switch call {
		case 1:
			return &fakeServer{
				client: &fakeClient{
					statusFn: func(ctx context.Context) (*ipnstate.Status, error) {
						return &ipnstate.Status{BackendState: ipn.Running.String()}, nil
					},
					watchIPNBusFn: func(ctx context.Context, mask ipn.NotifyWatchOpt) (ipnBusWatcher, error) {
						return &fakeWatcher{
							nextFn: func() (ipn.Notify, error) {
								<-ctx.Done()
								return ipn.Notify{}, ctx.Err()
							},
						}, nil
					},
				},
				closeFn: func() error {
					close(firstCloseStarted)
					<-allowFirstClose
					return nil
				},
			}
		case 2:
			return &fakeServer{
				startFn: func() error {
					close(secondStartCalled)
					return nil
				},
				client: &fakeClient{
					statusFn: func(ctx context.Context) (*ipnstate.Status, error) {
						return &ipnstate.Status{BackendState: ipn.Running.String()}, nil
					},
				},
			}
		default:
			t.Fatalf("unexpected server factory call: %d", call)
			return nil
		}
	}

	if err := ApplyConfig(Config{
		Enable:       true,
		AcceptRoutes: true,
		Dir:          stateDir,
		Hostname:     "test-host-1",
	}); err != nil {
		t.Fatalf("enable first tailscale server: %v", err)
	}

	if err := ApplyConfig(Config{Enable: false}); err != nil {
		t.Fatalf("disable tailscale: %v", err)
	}

	select {
	case <-firstCloseStarted:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("first server close did not start")
	}

	err := ApplyConfig(Config{
		Enable:       true,
		AcceptRoutes: true,
		Dir:          stateDir,
		Hostname:     "test-host-2",
	})
	if err == nil {
		t.Fatal("expected second enable to fail while previous close is still running")
	}
	if !strings.Contains(err.Error(), "previous tailscale server close still running") {
		t.Fatalf("unexpected enable error: %v", err)
	}

	select {
	case <-secondStartCalled:
		t.Fatal("second server started despite close timeout")
	default:
	}

	state := Snapshot()
	if !state.Enable {
		t.Fatal("expected state to reflect attempted enable after timeout")
	}
	if state.BackendState != ipn.Stopped.String() {
		t.Fatalf("unexpected backend state after timeout: %s", state.BackendState)
	}
	if !strings.Contains(state.Error, "previous tailscale server close still running") {
		t.Fatalf("unexpected state error after timeout: %q", state.Error)
	}

	close(allowFirstClose)
}

func TestSetErrorIgnoresStaleSession(t *testing.T) {
	m := newTestManager()
	m.session = 2
	m.state = State{BackendState: ipn.Starting.String()}

	m.setError(1, errors.New("socket down"))
	if m.state.Error != "" {
		t.Fatalf("stale error should be ignored, got %q", m.state.Error)
	}

	m.setError(2, errors.New("socket down"))
	if m.state.Error != "socket down" {
		t.Fatalf("current error should be recorded, got %q", m.state.Error)
	}
}

func TestDialTimeout(t *testing.T) {
	restoreTestHooks(t)
	tailscaleDialTimeout = 50 * time.Millisecond

	defaultManager = &manager{
		state: State{
			BackendState: ipn.Running.String(),
		},
		server: &fakeServer{
			dialFn: func(ctx context.Context, network, address string) (net.Conn, error) {
				<-ctx.Done()
				return nil, ctx.Err()
			},
		},
	}

	ctx := context.Background()
	done := make(chan struct{})
	var dialErr error

	go func() {
		defer close(done)
		_, dialErr = DialContext(ctx, "tcp", "10.0.0.1:80")
	}()

	select {
	case <-done:
		if dialErr == nil {
			t.Fatal("expected error when dial times out")
		}
	case <-time.After(time.Second):
		t.Fatal("dial blocked for too long")
	}
}

func TestConcurrentDial(t *testing.T) {
	defaultManager = &manager{
		state: State{
			BackendState: ipn.Running.String(),
		},
		server: nil,
	}

	const numDials = 10
	var wg sync.WaitGroup
	wg.Add(numDials)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	for i := 0; i < numDials; i++ {
		go func(id int) {
			defer wg.Done()
			_, err := DialContext(ctx, "tcp", "10.0.0.1:80")
			if err == nil {
				t.Errorf("goroutine %d: expected error, got nil", id)
			}
		}(i)
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("concurrent dials deadlocked")
	}
}

func TestMatchReentrancy(t *testing.T) {
	m := &manager{
		state: State{
			BackendState: ipn.Running.String(),
		},
		config: Config{
			Enable:       true,
			AcceptRoutes: true,
		},
		server: &fakeServer{},
		routes: []netip.Prefix{
			netip.MustParsePrefix("10.0.0.0/8"),
		},
	}

	dialID := uint64(1)
	m.activeDials.Store(dialID, time.Now())
	defer m.activeDials.Delete(dialID)

	addr := netip.MustParseAddr("10.0.0.1")
	if _, matched := m.match(addr, true); matched {
		t.Fatal("expected reentrancy protection to suppress match")
	}

	m.activeDials.Delete(dialID)
	if _, matched := m.match(addr, false); !matched {
		t.Fatal("expected route to match once reentrancy is cleared")
	}
}

func TestCloseCleanup(t *testing.T) {
	defaultManager = &manager{
		state: State{
			BackendState: ipn.Running.String(),
			Enable:       true,
		},
		config: Config{
			Enable:       true,
			AcceptRoutes: true,
		},
		routes: []netip.Prefix{
			netip.MustParsePrefix("10.0.0.0/8"),
		},
		disabledRoutes: []netip.Prefix{},
	}

	if err := Close(); err != nil {
		t.Fatalf("close tailscale: %v", err)
	}

	state := Snapshot()
	if state.Enable {
		t.Fatal("expected tailscale disabled after close")
	}
	if state.BackendState != ipn.Stopped.String() {
		t.Fatalf("unexpected backend state after close: %s", state.BackendState)
	}

	defaultManager.mu.Lock()
	defer defaultManager.mu.Unlock()
	if defaultManager.server != nil {
		t.Fatal("expected server to be nil after close")
	}
	if defaultManager.client != nil {
		t.Fatal("expected client to be nil after close")
	}
	if defaultManager.cancel != nil {
		t.Fatal("expected cancel to be nil after close")
	}
	if defaultManager.routes != nil {
		t.Fatal("expected routes to be nil after close")
	}
}

func BenchmarkMatch(b *testing.B) {
	m := &manager{
		state: State{
			BackendState: ipn.Running.String(),
		},
		config: Config{
			Enable:       true,
			AcceptRoutes: true,
		},
		routes: []netip.Prefix{
			netip.MustParsePrefix("10.0.0.0/8"),
			netip.MustParsePrefix("172.16.0.0/12"),
			netip.MustParsePrefix("192.168.0.0/16"),
		},
		server: &fakeServer{},
	}

	addr := netip.MustParseAddr("10.0.0.1")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.match(addr, false)
	}
}

func TestPeerRoutesIncludesPeerTailscaleIPs(t *testing.T) {
	peer := &ipnstate.PeerStatus{
		TailscaleIPs: []netip.Addr{
			netip.MustParseAddr("100.64.0.5"),
			netip.MustParseAddr("fd7a:115c:a1e0::5"),
		},
		AllowedIPs: ptrSliceView([]netip.Prefix{
			netip.MustParsePrefix("100.64.0.5/32"),
			netip.MustParsePrefix("fd7a:115c:a1e0::5/128"),
			netip.MustParsePrefix("192.168.1.0/24"),
		}),
	}

	routes := peerRoutes(peer)
	if !containsPrefix(routes, netip.MustParsePrefix("100.64.0.5/32")) {
		t.Fatalf("expected peer /32 in routes, got %v", routes)
	}
	if !containsPrefix(routes, netip.MustParsePrefix("fd7a:115c:a1e0::5/128")) {
		t.Fatalf("expected peer /128 in routes, got %v", routes)
	}
	if !containsPrefix(routes, netip.MustParsePrefix("192.168.1.0/24")) {
		t.Fatalf("expected subnet route in routes, got %v", routes)
	}
}

func TestPeerRoutesPreservesTailscaleIPsWithPrimaryRoutes(t *testing.T) {
	peer := &ipnstate.PeerStatus{
		TailscaleIPs: []netip.Addr{netip.MustParseAddr("100.64.0.7")},
		PrimaryRoutes: ptrSliceView([]netip.Prefix{
			netip.MustParsePrefix("10.1.0.0/16"),
		}),
		AllowedIPs: ptrSliceView([]netip.Prefix{
			netip.MustParsePrefix("100.64.0.7/32"),
			netip.MustParsePrefix("10.1.0.0/16"),
		}),
	}

	routes := peerRoutes(peer)
	if !containsPrefix(routes, netip.MustParsePrefix("100.64.0.7/32")) {
		t.Fatalf("expected peer /32 to be present when PrimaryRoutes is set, got %v", routes)
	}
	if !containsPrefix(routes, netip.MustParsePrefix("10.1.0.0/16")) {
		t.Fatalf("expected PrimaryRoute to be present, got %v", routes)
	}
}

func ptrSliceView(prefixes []netip.Prefix) *views.Slice[netip.Prefix] {
	v := views.SliceOf(prefixes)
	return &v
}

func containsPrefix(haystack []netip.Prefix, needle netip.Prefix) bool {
	for _, p := range haystack {
		if p == needle {
			return true
		}
	}
	return false
}

func TestMain(m *testing.M) {
	log.SetLevel(log.SILENT)
	os.Exit(m.Run())
}
