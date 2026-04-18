package tailscale

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
	"tailscale.com/client/tailscale"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
	tsnetlib "tailscale.com/tsnet"
	"tailscale.com/types/views"
)

type Config struct {
	Enable         bool
	AcceptRoutes   bool
	Dir            string
	Hostname       string
	AuthKey        string
	ControlURL     string
	DisabledRoutes []string
}

type State struct {
	Enable          bool     `json:"enable"`
	AcceptRoutes    bool     `json:"accept-routes"`
	BackendState    string   `json:"backend-state"`
	AuthURL         string   `json:"auth-url"`
	TailscaleIPs    []string `json:"tailscale-ips"`
	Routes          []string `json:"routes"`
	DisabledRoutes  []string `json:"disabled-routes"`
	Tailnet         string   `json:"tailnet"`
	MagicDNSSuffix  string   `json:"magic-dns-suffix"`
	Error           string   `json:"error"`
	PeerCount       int      `json:"peer-count"`
	OnlinePeerCount int      `json:"online-peer-count"`
	LastHandshake   string   `json:"last-handshake"`
}

type routeRule struct {
	prefix netip.Prefix
}

func (r routeRule) RuleType() C.RuleType {
	return C.IPCIDR
}

func (r routeRule) Match(_ *C.Metadata, _ C.RuleMatchHelper) (bool, string) {
	return true, tailscaleProxyName
}

func (r routeRule) Adapter() string {
	return tailscaleProxyName
}

func (r routeRule) Payload() string {
	return r.prefix.String()
}

func (r routeRule) ProviderNames() []string {
	return nil
}

type ipnBusWatcher interface {
	Next() (ipn.Notify, error)
	Close() error
}

type localClient interface {
	EditPrefs(ctx context.Context, mp *ipn.MaskedPrefs) (*ipn.Prefs, error)
	Status(ctx context.Context) (*ipnstate.Status, error)
	WatchIPNBus(ctx context.Context, mask ipn.NotifyWatchOpt) (ipnBusWatcher, error)
	Ping(ctx context.Context, ip netip.Addr, pingtype tailcfg.PingType) (*ipnstate.PingResult, error)
}

type tsnetServer interface {
	Start() error
	LocalClient() (localClient, error)
	Close() error
	Dial(ctx context.Context, network, address string) (net.Conn, error)
}

type localClientAdapter struct {
	client *tailscale.LocalClient
}

func (c *localClientAdapter) EditPrefs(ctx context.Context, mp *ipn.MaskedPrefs) (*ipn.Prefs, error) {
	return c.client.EditPrefs(ctx, mp)
}

func (c *localClientAdapter) Status(ctx context.Context) (*ipnstate.Status, error) {
	return c.client.Status(ctx)
}

func (c *localClientAdapter) WatchIPNBus(ctx context.Context, mask ipn.NotifyWatchOpt) (ipnBusWatcher, error) {
	return c.client.WatchIPNBus(ctx, mask)
}

func (c *localClientAdapter) Ping(ctx context.Context, ip netip.Addr, pingtype tailcfg.PingType) (*ipnstate.PingResult, error) {
	return c.client.Ping(ctx, ip, pingtype)
}

type tsnetServerAdapter struct {
	server *tsnetlib.Server
}

func (s *tsnetServerAdapter) Start() error {
	return s.server.Start()
}

func (s *tsnetServerAdapter) LocalClient() (localClient, error) {
	client, err := s.server.LocalClient()
	if err != nil {
		return nil, err
	}
	return &localClientAdapter{client: client}, nil
}

func (s *tsnetServerAdapter) Close() error {
	return s.server.Close()
}

func (s *tsnetServerAdapter) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	return s.server.Dial(ctx, network, address)
}

type manager struct {
	mu             sync.RWMutex
	config         Config
	state          State
	routes         []netip.Prefix
	disabledRoutes []netip.Prefix
	lastRouteLog   string
	proxy          C.Proxy

	server           tsnetServer
	client           localClient
	cancel           context.CancelFunc
	done             chan struct{}
	closingDone      chan struct{}
	session          uint64
	sessionStartedAt time.Time
	closingSession   uint64
	closingStartedAt time.Time

	// Track active dials for reentrancy protection (with timeout)
	activeDials sync.Map // map[uint64]time.Time
	nextDialID  uint64
}

const tailscaleProxyName = "TAILSCALE"

var (
	newTSNetServer = func(config Config) tsnetServer {
		return &tsnetServerAdapter{
			server: &tsnetlib.Server{
				Dir:        config.Dir,
				Hostname:   config.Hostname,
				AuthKey:    config.AuthKey,
				ControlURL: config.ControlURL,
				Logf: func(format string, args ...any) {
					log.Infoln("[TAILSCALE] "+format, args...)
				},
			},
		}
	}
	tailscaleRequestTimeout    = 10 * time.Second
	tailscaleWatcherExitWait   = 3 * time.Second
	tailscaleServerCloseWait   = 5 * time.Second
	tailscaleWatchRetryMax     = 3
	tailscaleWatchRetryBackoff = 5 * time.Second
	tailscaleWatchRetryCap     = 60 * time.Second
	tailscaleDialTimeout       = 10 * time.Second
)

func summarizeConfig(config Config) string {
	return fmt.Sprintf(
		"enable=%v acceptRoutes=%v dir=%q hostname=%q controlURL=%q authKeySet=%v disabledRoutes=%d",
		config.Enable,
		config.AcceptRoutes,
		config.Dir,
		config.Hostname,
		config.ControlURL,
		strings.TrimSpace(config.AuthKey) != "",
		len(config.DisabledRoutes),
	)
}

func elapsedSince(start time.Time) string {
	if start.IsZero() {
		return "unknown"
	}
	return time.Since(start).Round(time.Millisecond).String()
}

func durationBetween(start, end time.Time) string {
	if start.IsZero() || end.IsZero() {
		return "unknown"
	}
	return end.Sub(start).Round(time.Millisecond).String()
}

var defaultManager = &manager{
	state: State{
		BackendState: ipn.Stopped.String(),
	},
}

func ProxyName() string {
	return tailscaleProxyName
}

func SetProxy(proxy C.Proxy) {
	defaultManager.mu.Lock()
	defer defaultManager.mu.Unlock()
	defaultManager.proxy = proxy
}

func Proxy() C.Proxy {
	defaultManager.mu.RLock()
	defer defaultManager.mu.RUnlock()
	return defaultManager.proxy
}

func Snapshot() State {
	defaultManager.mu.RLock()
	defer defaultManager.mu.RUnlock()
	state := defaultManager.state
	log.Infoln("[TAILSCALE] Snapshot: backendState=%s enable=%v", state.BackendState, state.Enable)
	return state
}

func ApplyConfig(config Config) error {
	return defaultManager.applyConfig(config)
}

func Close() error {
	return defaultManager.close()
}

func Reconnect() error {
	return defaultManager.reconnect()
}

func Match(addr netip.Addr) (netip.Prefix, bool) {
	return defaultManager.match(addr, true)
}

func LookupRoute(addr netip.Addr) (netip.Prefix, bool) {
	return defaultManager.match(addr, false)
}

func DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return defaultManager.dialContext(ctx, network, address)
}

func Ping(ctx context.Context, addr netip.Addr) (*ipnstate.PingResult, error) {
	return defaultManager.ping(ctx, addr)
}

func RouteRule(prefix netip.Prefix) C.Rule {
	return routeRule{prefix: prefix}
}

func (m *manager) applyConfig(config Config) error {
	applyStartedAt := time.Now()
	config.Hostname = strings.TrimSpace(config.Hostname)
	config.AuthKey = strings.TrimSpace(config.AuthKey)
	config.ControlURL = strings.TrimSpace(config.ControlURL)
	disabledRoutes, normalizedDisabledRoutes := parsePrefixes(config.DisabledRoutes)
	config.DisabledRoutes = normalizedDisabledRoutes

	m.mu.Lock()
	currentEnable := m.config.Enable
	currentDir := m.config.Dir
	currentHostname := m.config.Hostname
	currentAuthKey := m.config.AuthKey
	currentControlURL := m.config.ControlURL
	currentSession := m.session
	server := m.server
	client := m.client
	m.mu.Unlock()

	log.Infoln(
		"[TAILSCALE] applyConfig called: requested={%s} currentSession=%d currentEnable=%v server=%v",
		summarizeConfig(config),
		currentSession,
		currentEnable,
		server != nil,
	)

	// Case 1: Disable Tailscale
	if !config.Enable {
		if currentEnable || server != nil {
			log.Infoln("[TAILSCALE] disabling tailscale from session=%d", currentSession)
			return m.close()
		}
		// Already disabled, just update config
		m.mu.Lock()
		m.config = config
		m.state.AcceptRoutes = config.AcceptRoutes
		m.state.DisabledRoutes = append([]string(nil), config.DisabledRoutes...)
		m.disabledRoutes = disabledRoutes
		m.mu.Unlock()
		log.Infoln("[TAILSCALE] already disabled, updated config in %s", elapsedSince(applyStartedAt))
		return nil
	}

	// Case 2: Enable Tailscale
	if config.Dir == "" {
		return errors.New("tailscale state dir is empty")
	}

	// Check if we need to start a new server (first time or critical config changed)
	needNewServer := server == nil ||
		currentDir != config.Dir ||
		currentHostname != config.Hostname ||
		currentAuthKey != config.AuthKey ||
		currentControlURL != config.ControlURL

	log.Infoln("[TAILSCALE] needNewServer=%v (server=%v, dirChanged=%v, hostChanged=%v, authChanged=%v, ctrlChanged=%v)",
		needNewServer, server == nil, currentDir != config.Dir, currentHostname != config.Hostname,
		currentAuthKey != config.AuthKey, currentControlURL != config.ControlURL)

	if needNewServer {
		// Close existing server if any
		if server != nil {
			log.Infoln("[TAILSCALE] closing existing server before starting new one: currentSession=%d", currentSession)
			if err := m.close(); err != nil {
				log.Warnln("[TAILSCALE] close old server error: %s", err.Error())
			}
			// After close(), m.server is nil, so re-check
			m.mu.Lock()
			server = m.server
			m.mu.Unlock()
		}
		if err := m.waitForServerClose(); err != nil {
			m.mu.Lock()
			m.config = config
			m.disabledRoutes = disabledRoutes
			m.state = State{
				Enable:         true,
				AcceptRoutes:   config.AcceptRoutes,
				BackendState:   ipn.Stopped.String(),
				DisabledRoutes: append([]string(nil), config.DisabledRoutes...),
				Error:          err.Error(),
			}
			m.mu.Unlock()
			return err
		}

		log.Infoln("[TAILSCALE] starting new server instance after %s", elapsedSince(applyStartedAt))
		newServer := newTSNetServer(config)
		serverStartAt := time.Now()

		if err := newServer.Start(); err != nil {
			log.Errorln("[TAILSCALE] server.Start() error after %s: %s", elapsedSince(serverStartAt), err.Error())
			m.mu.Lock()
			m.config = config
			m.state = State{
				Enable:         true,
				AcceptRoutes:   config.AcceptRoutes,
				BackendState:   ipn.Stopped.String(),
				DisabledRoutes: append([]string(nil), config.DisabledRoutes...),
				Error:          err.Error(),
			}
			m.mu.Unlock()
			return err
		}

		log.Infoln("[TAILSCALE] server started successfully in %s", elapsedSince(serverStartAt))

		clientStartAt := time.Now()
		newClient, err := newServer.LocalClient()
		if err != nil {
			_ = newServer.Close()
			m.mu.Lock()
			m.config = config
			m.state = State{
				Enable:         true,
				AcceptRoutes:   config.AcceptRoutes,
				BackendState:   ipn.Stopped.String(),
				DisabledRoutes: append([]string(nil), config.DisabledRoutes...),
				Error:          err.Error(),
			}
			m.mu.Unlock()
			log.Errorln("[TAILSCALE] LocalClient() error after %s: %s", elapsedSince(clientStartAt), err.Error())
			return err
		}
		log.Infoln("[TAILSCALE] LocalClient() ready in %s", elapsedSince(clientStartAt))

		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		sessionStartedAt := time.Now()

		m.mu.Lock()
		session := m.session + 1
		m.session = session
		m.sessionStartedAt = sessionStartedAt
		m.config = config
		m.server = newServer
		m.client = newClient
		m.cancel = cancel
		m.done = done
		m.disabledRoutes = disabledRoutes
		m.state = State{
			Enable:         true,
			AcceptRoutes:   config.AcceptRoutes,
			BackendState:   ipn.Starting.String(),
			DisabledRoutes: append([]string(nil), config.DisabledRoutes...),
		}
		m.mu.Unlock()

		if err := m.updatePrefs(session, newClient, config.AcceptRoutes); err != nil {
			// Don't fail on updatePrefs error, just log it
			log.Warnln("[TAILSCALE] update prefs error: %s", err.Error())
		}

		if err := m.refreshStatus(session, newClient); err != nil {
			log.Warnln("[TAILSCALE] refresh status error: %s", err.Error())
		}

		go m.watch(ctx, session, newClient, done)
		log.Infoln(
			"[TAILSCALE] watcher started: session=%d startup=%s requested={%s}",
			session,
			elapsedSince(applyStartedAt),
			summarizeConfig(config),
		)
		return nil
	}

	// Case 3: Server already running, just update preferences and disabled routes
	log.Infoln("[TAILSCALE] server already running, updating prefs only for session=%d", currentSession)
	m.mu.Lock()
	m.config = config
	m.disabledRoutes = disabledRoutes
	m.state.DisabledRoutes = append([]string(nil), config.DisabledRoutes...)
	currentSession = m.session
	m.mu.Unlock()

	return m.updatePrefs(currentSession, client, config.AcceptRoutes)
}

func (m *manager) updatePrefs(session uint64, client localClient, acceptRoutes bool) error {
	if client == nil {
		return nil
	}

	updateStartedAt := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), tailscaleRequestTimeout)
	defer cancel()

	_, err := client.EditPrefs(ctx, &ipn.MaskedPrefs{
		Prefs: ipn.Prefs{
			RouteAll:    acceptRoutes,
			WantRunning: true,
		},
		RouteAllSet:    true,
		WantRunningSet: true,
	})
	if err != nil {
		return fmt.Errorf("update tailscale prefs: %w", err)
	}

	m.mu.Lock()
	if session != m.session {
		currentSession := m.session
		m.mu.Unlock()
		log.Infoln("[TAILSCALE] updatePrefs ignored for stale session=%d currentSession=%d", session, currentSession)
		return nil
	}
	m.state.AcceptRoutes = acceptRoutes
	m.config.AcceptRoutes = acceptRoutes
	m.mu.Unlock()
	log.Infoln("[TAILSCALE] updatePrefs completed: session=%d acceptRoutes=%v elapsed=%s", session, acceptRoutes, elapsedSince(updateStartedAt))
	return m.refreshStatus(session, client)
}

func (m *manager) close() error {
	closeStartedAt := time.Now()

	m.mu.Lock()
	closingSession := m.session
	server := m.server
	cancel := m.cancel
	done := m.done
	oldState := m.state
	wasEnabled := m.config.Enable
	sessionStartedAt := m.sessionStartedAt
	closeDone := m.closingDone
	if server != nil {
		closeDone = make(chan struct{})
		m.closingDone = closeDone
		m.closingSession = closingSession
		m.closingStartedAt = closeStartedAt
	}
	m.session++
	m.server = nil
	m.client = nil
	m.cancel = nil
	m.done = nil
	m.sessionStartedAt = time.Time{}
	m.routes = nil
	m.disabledRoutes = nil
	m.lastRouteLog = ""
	m.config.Enable = false
	m.state = State{
		Enable:         false,
		AcceptRoutes:   oldState.AcceptRoutes,
		BackendState:   ipn.Stopped.String(),
		DisabledRoutes: append([]string(nil), oldState.DisabledRoutes...),
	}
	m.mu.Unlock()

	log.Infoln(
		"[TAILSCALE] close() called: closingSession=%d wasEnabled=%v sessionLifetime=%s",
		closingSession,
		wasEnabled,
		durationBetween(sessionStartedAt, closeStartedAt),
	)
	log.Infoln("[TAILSCALE] close() state cleared for session=%d", closingSession)

	// Signal cancellation first
	if cancel != nil {
		cancel()
	}

	// Wait for watcher goroutine to exit with timeout
	if done != nil {
		watchWaitStartedAt := time.Now()
		select {
		case <-done:
			log.Infoln("[TAILSCALE] watcher exited cleanly for session=%d after wait=%s", closingSession, elapsedSince(watchWaitStartedAt))
		case <-time.After(tailscaleWatcherExitWait):
			log.Warnln("[TAILSCALE] watcher didn't exit in time for session=%d after wait=%s", closingSession, elapsedSince(watchWaitStartedAt))
		}
	}

	// Close server in background to avoid blocking
	if server != nil {
		serverCloseStartedAt := time.Now()
		go func() {
			defer func() {
				close(closeDone)
				m.clearClosingDone(closeDone)
				if r := recover(); r != nil {
					log.Warnln("[TAILSCALE] panic during server close: session=%d elapsed=%s panic=%v", closingSession, elapsedSince(serverCloseStartedAt), r)
				}
			}()
			log.Infoln("[TAILSCALE] closing tsnet server for session=%d", closingSession)
			if err := server.Close(); err != nil {
				log.Warnln("[TAILSCALE] server close error: session=%d elapsed=%s err=%s", closingSession, elapsedSince(serverCloseStartedAt), err.Error())
			} else {
				log.Infoln("[TAILSCALE] server closed successfully: session=%d elapsed=%s", closingSession, elapsedSince(serverCloseStartedAt))
			}
		}()
	}

	log.Infoln("[TAILSCALE] close() returned for session=%d after %s", closingSession, elapsedSince(closeStartedAt))
	return nil
}

func (m *manager) reconnect() error {
	m.mu.RLock()
	config := m.config
	currentSession := m.session
	m.mu.RUnlock()

	if !config.Enable {
		return errors.New("tailscale is not enabled")
	}

	reconnectStartedAt := time.Now()
	log.Infoln("[TAILSCALE] reconnect requested for session=%d requested={%s}", currentSession, summarizeConfig(config))
	if err := m.close(); err != nil {
		return fmt.Errorf("close tailscale: %w", err)
	}
	if err := m.applyConfig(config); err != nil {
		return err
	}
	log.Infoln("[TAILSCALE] reconnect completed from session=%d in %s", currentSession, elapsedSince(reconnectStartedAt))
	return nil
}

func (m *manager) waitForServerClose() error {
	waitStartedAt := time.Now()
	m.mu.RLock()
	closeDone := m.closingDone
	closingSession := m.closingSession
	closingStartedAt := m.closingStartedAt
	m.mu.RUnlock()

	if closeDone == nil {
		return nil
	}

	log.Infoln(
		"[TAILSCALE] waiting for previous server close: closingSession=%d closeElapsed=%s",
		closingSession,
		elapsedSince(closingStartedAt),
	)
	select {
	case <-closeDone:
		log.Infoln(
			"[TAILSCALE] previous server close completed: closingSession=%d wait=%s totalClose=%s",
			closingSession,
			elapsedSince(waitStartedAt),
			elapsedSince(closingStartedAt),
		)
		return nil
	case <-time.After(tailscaleServerCloseWait):
		err := fmt.Errorf("previous tailscale server close still running after %s", tailscaleServerCloseWait)
		log.Warnln(
			"[TAILSCALE] %s (closingSession=%d wait=%s totalClose=%s)",
			err.Error(),
			closingSession,
			elapsedSince(waitStartedAt),
			elapsedSince(closingStartedAt),
		)
		return err
	}
}

func (m *manager) clearClosingDone(target chan struct{}) {
	if target == nil {
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closingDone == target {
		m.closingDone = nil
		m.closingSession = 0
		m.closingStartedAt = time.Time{}
	}
}

func (m *manager) watch(
	ctx context.Context,
	session uint64,
	client localClient,
	done chan struct{},
) {
	watchStartedAt := time.Now()
	defer close(done)
	defer log.Infoln("[TAILSCALE] watch goroutine exited: session=%d lifetime=%s", session, elapsedSince(watchStartedAt))
	defer func() {
		if r := recover(); r != nil {
			log.Errorln("[TAILSCALE] panic in watch goroutine: session=%d lifetime=%s panic=%v", session, elapsedSince(watchStartedAt), r)
			m.setError(session, fmt.Errorf("watch panic: %v", r))
		}
	}()

	backoff := tailscaleWatchRetryBackoff

	for attempt := 0; ; attempt++ {
		if ctx.Err() != nil {
			log.Infoln("[TAILSCALE] watch loop exiting: session=%d context cancelled", session)
			return
		}
		if attempt > 0 {
			if attempt > tailscaleWatchRetryMax {
				log.Warnln("[TAILSCALE] watcher gave up: session=%d retries=%d", session, tailscaleWatchRetryMax)
				m.setError(session, fmt.Errorf("watcher stopped after %d retries", tailscaleWatchRetryMax))
				return
			}
			log.Warnln("[TAILSCALE] restarting watcher: session=%d attempt=%d/%d", session, attempt, tailscaleWatchRetryMax)
			select {
			case <-time.After(backoff):
				backoff = min(backoff*2, tailscaleWatchRetryCap)
			case <-ctx.Done():
				log.Infoln("[TAILSCALE] watch loop exiting: session=%d context cancelled during backoff", session)
				return
			}
		}

		if err := m.runWatcher(ctx, session, client); err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Warnln("[TAILSCALE] watcher error: session=%d attempt=%d source=runWatcher err=%s", session, attempt, err.Error())
			continue
		}
		return
	}
}

func (m *manager) runWatcher(
	ctx context.Context,
	session uint64,
	client localClient,
) error {
	log.Infoln("[TAILSCALE] runWatcher subscribe: session=%d", session)
	watcher, err := client.WatchIPNBus(
		ctx,
		ipn.NotifyInitialState|
			ipn.NotifyInitialNetMap|
			ipn.NotifyInitialPrefs|
			ipn.NotifyNoPrivateKeys,
	)
	if err != nil {
		if ctx.Err() == nil {
			m.setError(session, err)
		}
		log.Warnln("[TAILSCALE] watcher subscribe error: session=%d source=WatchIPNBus err=%s", session, err.Error())
		return err
	}
	defer func() {
		if err := watcher.Close(); err != nil {
			log.Warnln("[TAILSCALE] watcher close error: session=%d err=%s", session, err.Error())
		}
	}()

	healthTicker := time.NewTicker(30 * time.Second)
	defer healthTicker.Stop()

	type watchResult struct {
		notify ipn.Notify
		err    error
	}
	ch := make(chan watchResult, 1)

	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Errorln("[TAILSCALE] panic in watcher reader: session=%d panic=%v", session, r)
				select {
				case ch <- watchResult{err: fmt.Errorf("watcher reader panic: %v", r)}:
				default:
				}
			}
		}()
		for {
			n, err := watcher.Next()
			if err != nil && ctx.Err() == nil {
				log.Warnln("[TAILSCALE] watcher next error: session=%d source=watcher.Next err=%s", session, err.Error())
			}
			select {
			case ch <- watchResult{n, err}:
			case <-ctx.Done():
				return
			}
			if err != nil {
				return
			}
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return nil
		case wr := <-ch:
			if ctx.Err() != nil {
				return nil
			}
			if wr.err != nil {
				m.setError(session, wr.err)
				return wr.err
			}
			m.handleNotification(session, &wr.notify)
			if err := m.refreshStatus(session, client); err != nil && ctx.Err() == nil {
				log.Warnln("[TAILSCALE] refresh status error: %s", err.Error())
			}
		case <-healthTicker.C:
			if err := m.refreshStatus(session, client); err != nil && ctx.Err() == nil {
				log.Warnln("[TAILSCALE] periodic refresh error: %s", err.Error())
			}
		}
	}
}

func (m *manager) handleNotification(session uint64, notify *ipn.Notify) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if session != m.session {
		log.Infoln("[TAILSCALE] ignoring stale notification: session=%d currentSession=%d", session, m.session)
		return
	}
	if notify.BrowseToURL != nil {
		m.state.AuthURL = *notify.BrowseToURL
		log.Infoln("[TAILSCALE] notification: AuthURL updated")
	}
	if notify.ErrMessage != nil {
		m.state.Error = *notify.ErrMessage
		log.Infoln("[TAILSCALE] notification: Error=%s", *notify.ErrMessage)
	}
	if notify.State != nil {
		oldState := m.state.BackendState
		nextState := notify.State.String()
		if nextState == ipn.NoState.String() && oldState == ipn.Starting.String() {
			log.Infoln("[TAILSCALE] preventing NoState notification from overwriting Starting")
			nextState = oldState
		}
		m.state.BackendState = nextState
		log.Infoln("[TAILSCALE] notification: state changed from %s to %s", oldState, nextState)
		if *notify.State == ipn.Running {
			m.state.AuthURL = ""
			m.state.Error = ""
		}
	}
}

func (m *manager) refreshStatus(session uint64, client localClient) error {
	if client == nil {
		log.Infoln("[TAILSCALE] refreshStatus skipped: session=%d client=nil", session)
		return nil
	}

	refreshStartedAt := time.Now()
	m.mu.RLock()
	if session != m.session {
		currentSession := m.session
		m.mu.RUnlock()
		log.Infoln("[TAILSCALE] refreshStatus ignored before request: session=%d currentSession=%d", session, currentSession)
		return nil
	}
	config := m.config
	m.mu.RUnlock()

	ctx, cancel := context.WithTimeout(context.Background(), tailscaleRequestTimeout)
	defer cancel()

	status, err := client.Status(ctx)
	if err != nil {
		m.setError(session, err)
		return err
	}

	routes := collectRoutes(status)
	routeStrings := make([]string, 0, len(routes))
	for _, route := range routes {
		routeStrings = append(routeStrings, route.String())
	}

	tailscaleIPs := make([]string, 0, len(status.TailscaleIPs))
	for _, addr := range status.TailscaleIPs {
		tailscaleIPs = append(tailscaleIPs, addr.String())
	}

	magicDNSSuffix := status.MagicDNSSuffix
	tailnet := ""
	if status.CurrentTailnet != nil {
		tailnet = status.CurrentTailnet.Name
		if status.CurrentTailnet.MagicDNSSuffix != "" {
			magicDNSSuffix = status.CurrentTailnet.MagicDNSSuffix
		}
	}

	peerCount := 0
	onlinePeerCount := 0
	var latestHandshake time.Time
	for _, peer := range status.Peer {
		if peer == nil {
			continue
		}
		peerCount++
		if peer.Online {
			onlinePeerCount++
		}
		if !peer.LastHandshake.IsZero() && peer.LastHandshake.After(latestHandshake) {
			latestHandshake = peer.LastHandshake
		}
	}

	lastHandshakeStr := ""
	if !latestHandshake.IsZero() {
		lastHandshakeStr = latestHandshake.UTC().Format(time.RFC3339)
	}

	routeLog := buildRouteLog(status, routes, config.DisabledRoutes)

	routeLogToPrint := ""
	m.mu.Lock()
	if session != m.session {
		currentSession := m.session
		m.mu.Unlock()
		log.Infoln("[TAILSCALE] refreshStatus ignored after request: session=%d currentSession=%d elapsed=%s", session, currentSession, elapsedSince(refreshStartedAt))
		return nil
	}
	authURL := ""
	if status.BackendState != ipn.Running.String() {
		authURL = firstNonEmpty(status.AuthURL, m.state.AuthURL)
	}
	m.routes = routes
	if routeLog != m.lastRouteLog {
		m.lastRouteLog = routeLog
		routeLogToPrint = routeLog
	}
	// Don't let NoState overwrite Starting during startup
	backendState := status.BackendState
	if backendState == ipn.NoState.String() && m.state.BackendState == ipn.Starting.String() {
		backendState = ipn.Starting.String()
		log.Infoln("[TAILSCALE] preventing NoState from overwriting Starting")
	}
	m.state = State{
		Enable:          config.Enable,
		AcceptRoutes:    config.AcceptRoutes,
		BackendState:    backendState,
		AuthURL:         authURL,
		TailscaleIPs:    tailscaleIPs,
		Routes:          routeStrings,
		DisabledRoutes:  append([]string(nil), config.DisabledRoutes...),
		Tailnet:         tailnet,
		MagicDNSSuffix:  magicDNSSuffix,
		Error:           "",
		PeerCount:       peerCount,
		OnlinePeerCount: onlinePeerCount,
		LastHandshake:   lastHandshakeStr,
	}
	m.mu.Unlock()

	if routeLogToPrint != "" {
		log.Infoln("[TAILSCALE] %s", routeLogToPrint)
	}
	log.Infoln(
		"[TAILSCALE] refreshStatus completed: session=%d elapsed=%s backendState=%s raw=%s enable=%v peers=%d onlinePeers=%d",
		session,
		elapsedSince(refreshStartedAt),
		backendState,
		status.BackendState,
		config.Enable,
		peerCount,
		onlinePeerCount,
	)
	return nil
}

func (m *manager) setError(session uint64, err error) {
	if err == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if session != m.session {
		log.Infoln("[TAILSCALE] ignoring stale error: session=%d currentSession=%d err=%s", session, m.session, err.Error())
		return
	}
	m.state.Error = err.Error()
	log.Warnln("[TAILSCALE] state error updated: session=%d err=%s", session, err.Error())
}

func (m *manager) match(addr netip.Addr, requireProxy bool) (netip.Prefix, bool) {
	// Check for reentrancy - are we inside a Tailscale dial?
	// Only consider dials started in the last 30 seconds to avoid stale entries
	now := time.Now()
	hasActiveDial := false
	m.activeDials.Range(func(_, v interface{}) bool {
		startTime := v.(time.Time)
		if now.Sub(startTime) < 30*time.Second {
			hasActiveDial = true
			return false // stop iteration
		}
		return true // continue
	})
	if hasActiveDial {
		return netip.Prefix{}, false
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	if !m.config.Enable || !m.config.AcceptRoutes || !addr.IsValid() {
		return netip.Prefix{}, false
	}
	if requireProxy && m.proxy == nil {
		return netip.Prefix{}, false
	}
	// Don't match routes when tsnet isn't healthy — let traffic fall through
	// to normal Clash rules (typically DIRECT) instead of black-holing it.
	if m.server == nil || m.state.BackendState != ipn.Running.String() {
		return netip.Prefix{}, false
	}

	for _, prefix := range m.routes {
		if prefix.Contains(addr) {
			if routeDisabled(prefix, m.disabledRoutes) {
				continue
			}
			return prefix, true
		}
	}

	return netip.Prefix{}, false
}

func (m *manager) dialContext(ctx context.Context, network, address string) (conn net.Conn, err error) {
	defer func() {
		if r := recover(); r != nil {
			log.Errorln("[TAILSCALE] panic in server.Dial(%s, %s): %v", network, address, r)
			conn = nil
			err = fmt.Errorf("tailscale dial panic: %v", r)
		}
	}()

	m.mu.RLock()
	server := m.server
	backendState := m.state.BackendState
	m.mu.RUnlock()

	if server == nil {
		return nil, errors.New("tailscale is not started")
	}
	if backendState != ipn.Running.String() {
		return nil, fmt.Errorf("tailscale is %s", backendState)
	}

	// Register this dial for reentrancy protection
	dialID := atomic.AddUint64(&m.nextDialID, 1)
	m.activeDials.Store(dialID, time.Now())
	defer m.activeDials.Delete(dialID)

	// Use a goroutine to prevent tsnet internal deadlocks from blocking the core
	type dialResult struct {
		conn net.Conn
		err  error
	}
	resultCh := make(chan dialResult, 1)

	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Errorln("[TAILSCALE] panic in dial goroutine: %v", r)
				select {
				case resultCh <- dialResult{nil, fmt.Errorf("dial panic: %v", r)}:
				default:
				}
			}
		}()
		c, e := server.Dial(ctx, network, address)
		select {
		case resultCh <- dialResult{c, e}:
		default:
			// Channel full, close connection to avoid leak
			if c != nil {
				c.Close()
			}
		}
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case result := <-resultCh:
		return result.conn, result.err
	case <-time.After(tailscaleDialTimeout):
		return nil, errors.New("tailscale dial timeout")
	}
}

func (m *manager) ping(
	ctx context.Context,
	addr netip.Addr,
) (result *ipnstate.PingResult, err error) {
	defer func() {
		if r := recover(); r != nil {
			log.Errorln("[TAILSCALE] panic in ping: %v", r)
			result = nil
			err = fmt.Errorf("tailscale ping panic: %v", r)
		}
	}()

	m.mu.RLock()
	client := m.client
	config := m.config
	backendState := m.state.BackendState
	m.mu.RUnlock()

	if !config.Enable {
		return nil, errors.New("tailscale is not enabled")
	}
	if !config.AcceptRoutes {
		return nil, errors.New("tailscale routes are not accepted")
	}
	if !addr.IsValid() {
		return nil, errors.New("invalid ping address")
	}
	if client == nil {
		return nil, errors.New("tailscale is not started")
	}
	if backendState != ipn.Running.String() {
		return nil, fmt.Errorf("tailscale is %s", backendState)
	}

	result, err = client.Ping(ctx, addr, tailcfg.PingICMP)
	if err != nil {
		return nil, fmt.Errorf("tailscale ping: %w", err)
	}
	if result == nil {
		return nil, errors.New("tailscale ping returned no result")
	}
	if strings.TrimSpace(result.Err) != "" {
		return result, errors.New(result.Err)
	}
	return result, nil
}

func collectRoutes(status *ipnstate.Status) []netip.Prefix {
	if status == nil {
		return nil
	}

	var routes []netip.Prefix
	seen := map[string]struct{}{}

	for _, peer := range status.Peer {
		if peer == nil {
			continue
		}

		for _, prefix := range peerRoutes(peer) {
			if isDefaultRoute(prefix) {
				continue
			}
			key := prefix.String()
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			routes = append(routes, prefix)
		}
	}

	slices.SortFunc(routes, func(a, b netip.Prefix) int {
		if a.Bits() != b.Bits() {
			return b.Bits() - a.Bits()
		}
		return strings.Compare(a.String(), b.String())
	})
	return routes
}

func peerRoutes(peer *ipnstate.PeerStatus) []netip.Prefix {
	if peer.PrimaryRoutes != nil && !peer.PrimaryRoutes.IsNil() {
		return append([]netip.Prefix(nil), peer.PrimaryRoutes.AsSlice()...)
	}

	if peer.AllowedIPs == nil || peer.AllowedIPs.IsNil() {
		return nil
	}

	tailscaleIPs := map[netip.Addr]struct{}{}
	for _, addr := range peer.TailscaleIPs {
		tailscaleIPs[addr] = struct{}{}
	}

	var routes []netip.Prefix
	for _, prefix := range peer.AllowedIPs.AsSlice() {
		if _, ok := tailscaleIPs[prefix.Addr()]; ok && prefix.Bits() == prefix.Addr().BitLen() {
			continue
		}
		routes = append(routes, prefix)
	}
	return routes
}

func isDefaultRoute(prefix netip.Prefix) bool {
	return prefix.Bits() == 0
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func parsePrefixes(values []string) ([]netip.Prefix, []string) {
	if len(values) == 0 {
		return nil, nil
	}

	seen := map[string]struct{}{}
	prefixes := make([]netip.Prefix, 0, len(values))
	normalized := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			log.Warnln("[TAILSCALE] ignore invalid route prefix %q", value)
			continue
		}
		key := prefix.String()
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		prefixes = append(prefixes, prefix)
		normalized = append(normalized, key)
	}

	slices.Sort(normalized)
	slices.SortFunc(prefixes, func(a, b netip.Prefix) int {
		return strings.Compare(a.String(), b.String())
	})
	return prefixes, normalized
}

func routeDisabled(route netip.Prefix, disabled []netip.Prefix) bool {
	for _, prefix := range disabled {
		if prefix == route {
			return true
		}
	}
	return false
}

func buildRouteLog(
	status *ipnstate.Status,
	routes []netip.Prefix,
	disabledRoutes []string,
) string {
	if status == nil {
		return "route snapshot: status=<nil>"
	}

	lines := []string{
		fmt.Sprintf(
			"route snapshot: backend=%s self=%s peers=%d routes=%s disabled=%s",
			status.BackendState,
			formatAddrList(status.TailscaleIPs),
			len(status.Peer),
			formatPrefixList(routes),
			formatStringList(disabledRoutes),
		),
	}

	for _, key := range status.Peers() {
		peer := status.Peer[key]
		if peer == nil {
			continue
		}

		candidateRoutes := peerRoutes(peer)
		usableRoutes := make([]netip.Prefix, 0, len(candidateRoutes))
		for _, prefix := range candidateRoutes {
			if isDefaultRoute(prefix) {
				continue
			}
			usableRoutes = append(usableRoutes, prefix)
		}

		lines = append(
			lines,
			fmt.Sprintf(
				"route peer: name=%s id=%v online=%t active=%t exit=%t exitOption=%t primary=%s allowed=%s tailscale=%s candidate=%s usable=%s",
				peerDisplayName(peer),
				peer.ID,
				peer.Online,
				peer.Active,
				peer.ExitNode,
				peer.ExitNodeOption,
				formatPrefixList(slicePrefixes(peer.PrimaryRoutes)),
				formatPrefixList(slicePrefixes(peer.AllowedIPs)),
				formatAddrList(peer.TailscaleIPs),
				formatPrefixList(candidateRoutes),
				formatPrefixList(usableRoutes),
			),
		)
	}

	return strings.Join(lines, " | ")
}

func peerDisplayName(peer *ipnstate.PeerStatus) string {
	if peer == nil {
		return "<nil>"
	}
	if value := strings.TrimSpace(peer.HostName); value != "" {
		return value
	}
	if value := strings.TrimSpace(strings.TrimSuffix(peer.DNSName, ".")); value != "" {
		return value
	}
	return fmt.Sprintf("%v", peer.ID)
}

func formatPrefixList(prefixes []netip.Prefix) string {
	if len(prefixes) == 0 {
		return "[]"
	}
	values := make([]string, 0, len(prefixes))
	for _, prefix := range prefixes {
		values = append(values, prefix.String())
	}
	return "[" + strings.Join(values, ", ") + "]"
}

func formatAddrList(addrs []netip.Addr) string {
	if len(addrs) == 0 {
		return "[]"
	}
	values := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		values = append(values, addr.String())
	}
	return "[" + strings.Join(values, ", ") + "]"
}

func formatStringList(values []string) string {
	if len(values) == 0 {
		return "[]"
	}
	return "[" + strings.Join(values, ", ") + "]"
}

func slicePrefixes(prefixes *views.Slice[netip.Prefix]) []netip.Prefix {
	if prefixes == nil || prefixes.IsNil() {
		return nil
	}
	return append([]netip.Prefix(nil), prefixes.AsSlice()...)
}
