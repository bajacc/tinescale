package stunPool

import (
	"context"
	"fmt"
	"maps"
	"net"
	"sync"
	"time"

	"github.com/pion/stun"
	wgdevice "golang.zx2c4.com/wireguard/device"
)

type StunResult struct {
	LocalIP    net.IP
	PublicIP   net.IP
	PublicPort int
	Timestamp  time.Time
}

type StunPool interface {
	AddServer(addr string) error
	RemoveServer(addr string)
	GetAllResults() map[string]*StunResult
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
	results map[string]*StunResult

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
		results:     make(map[string]*StunResult),
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

func (s *stunPool) GetAllResults() map[string]*StunResult {
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
	s.results = make(map[string]*StunResult)
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
			s.log.Verbosef("STUN Query %s", addr)
			r, err := s.querySTUN(ctx, addr)

			if err != nil {
				s.log.Errorf("STUN query failed for %s: %v", addr, err)
				continue
			} else {
				s.log.Verbosef("STUN query successful for %s %v", addr, r)
			}

			s.mu.Lock()
			s.results[addr] = r
			s.mu.Unlock()

		}
	}
}

func (s *stunPool) querySTUN(ctx context.Context, serverAddr string) (*StunResult, error) {
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	var d net.Dialer
	conn, err := d.DialContext(ctx, "udp", serverAddr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	localUDPAddr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return nil, fmt.Errorf("expected UDPAddr, got %T", conn.LocalAddr())
	}
	localIP := localUDPAddr.IP

	c, err := stun.NewClient(conn)
	if err != nil {
		return nil, err
	}
	defer c.Close()

	var ip net.IP
	var port int

	message := stun.MustBuild(stun.TransactionID, stun.BindingRequest)
	var errRes error
	errDo := c.Do(message, func(res stun.Event) {
		if res.Error != nil {
			errRes = res.Error
			return
		}
		var xorAddr stun.XORMappedAddress
		if err = xorAddr.GetFrom(res.Message); err == nil {
			ip = xorAddr.IP
			port = xorAddr.Port
			return
		}
		s.log.Verbosef("XORMappedAddress not found: %v", err)

		var mappedAddr stun.MappedAddress
		if err = mappedAddr.GetFrom(res.Message); err == nil {
			ip = mappedAddr.IP
			port = mappedAddr.Port
			return
		}
		s.log.Verbosef("MappedAddress also not found: %v", err)
	})
	if errDo != nil {
		return nil, errDo
	}
	if errRes != nil {
		return nil, errRes
	}
	return &StunResult{
		PublicIP:   ip,
		PublicPort: port,
		LocalIP:    localIP,
		Timestamp:  time.Now(),
	}, nil
}
