package stunPool

import (
	"context"
	"maps"
	"net"
	"sync"
	"time"

	"github.com/pion/stun"
	wgdevice "golang.zx2c4.com/wireguard/device"
)

type StunResult struct {
	PublicIP   net.IP
	PublicPort int
	Err        error
	Timestamp  time.Time
}

type StunPool interface {
	AddServer(addr string) error
	RemoveServer(addr string)
	GetAllResults() map[string]StunResult
	GetAddresses() []string
	Clear()
	Close()
}

type stunPool struct {
	log         *wgdevice.Logger
	refreshTime time.Duration
	timeout     time.Duration

	mu      sync.RWMutex
	servers map[string]*serverState
	results map[string]StunResult

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

type serverState struct {
	addr   string
	cancel context.CancelFunc
}

func New(refreshInterval time.Duration, timeout time.Duration, logger *wgdevice.Logger) StunPool {
	ctx, cancel := context.WithCancel(context.Background())
	return &stunPool{
		log:         logger,
		refreshTime: refreshInterval,
		timeout:     timeout,
		servers:     make(map[string]*serverState),
		results:     make(map[string]StunResult),
		ctx:         ctx,
		cancel:      cancel,
	}
}

func (s *stunPool) AddServer(addr string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.servers[addr]; exists {
		return nil
	}

	serverCtx, serverCancel := context.WithCancel(s.ctx)
	s.servers[addr] = &serverState{
		addr:   addr,
		cancel: serverCancel,
	}

	s.wg.Add(1)
	go s.queryLoop(serverCtx, addr)

	return nil
}

func (s *stunPool) RemoveServer(addr string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if state, exists := s.servers[addr]; exists {
		state.cancel()
		delete(s.servers, addr)
		delete(s.results, addr)
	}
}

func (s *stunPool) GetAddresses() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	addrs := make([]string, 0, len(s.servers))
	for addr := range s.servers {
		addrs = append(addrs, addr)
	}
	return addrs
}

func (s *stunPool) GetAllResults() map[string]StunResult {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return maps.Clone(s.results)
}

func (s *stunPool) Clear() {

	s.mu.Lock()
	defer s.mu.Unlock()

	for _, state := range s.servers {
		state.cancel()
	}
	s.wg.Wait()

	s.servers = make(map[string]*serverState)
	s.results = make(map[string]StunResult)
}

func (s *stunPool) Close() {
	s.cancel()
	s.wg.Wait()
}

func (s *stunPool) queryLoop(ctx context.Context, addr string) {
	defer s.wg.Done()

	ticker := time.NewTicker(s.refreshTime)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			ip, port, err := s.querySTUN(ctx, addr)

			s.mu.Lock()
			s.results[addr] = StunResult{
				PublicIP:   ip,
				PublicPort: port,
				Err:        err,
				Timestamp:  time.Now(),
			}
			s.mu.Unlock()

			if err != nil {
				s.log.Errorf("STUN query failed for %s: %v", addr, err)
			} else {
				s.log.Verbosef("STUN query successful for %s: %s:%d", addr, ip, port)
			}
		}
	}
}

func (s *stunPool) querySTUN(ctx context.Context, serverAddr string) (net.IP, int, error) {
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	var d net.Dialer
	conn, err := d.DialContext(ctx, "udp", serverAddr)
	if err != nil {
		return nil, 0, err
	}
	defer conn.Close()

	c, err := stun.NewClient(conn)
	if err != nil {
		return nil, 0, err
	}
	defer c.Close()

	var xorAddr stun.XORMappedAddress

	message := stun.MustBuild(stun.TransactionID, stun.BindingRequest)
	err = c.Do(message, func(res stun.Event) {
		if res.Error != nil {
			err = res.Error
			return
		}
		err = xorAddr.GetFrom(res.Message)
	})
	return xorAddr.IP, xorAddr.Port, err
}
