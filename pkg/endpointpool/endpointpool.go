//go:generate protoc --go_out=paths=source_relative:. endpointpool.proto
package endpointpool

import (
	"context"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	wgdevice "golang.zx2c4.com/wireguard/device"
)

type EndpointPool interface {
	Clear()
	Close()

	GetAllEndpoints(pubKey wgdevice.NoisePublicKey) []conn.Endpoint
	AddPeer(key wgdevice.NoisePublicKey)
	RemovePeer(key wgdevice.NoisePublicKey)
}

type endpointPool struct {
	log  *wgdevice.Logger
	mu   sync.RWMutex
	wg   sync.WaitGroup
	pool map[wgdevice.NoisePublicKey]*peerEndpoints

	bind           conn.Bind
	updateInterval time.Duration
	requestTimeout time.Duration
	ctx            context.Context
	cancel         context.CancelFunc
}

type peerEndpoints struct {
	mu     sync.RWMutex
	cancel context.CancelFunc
	eps    []conn.Endpoint
}

func New(logger *wgdevice.Logger, bind conn.Bind, updateInterval time.Duration) EndpointPool {
	ctx, cancel := context.WithCancel(context.Background())

	return &endpointPool{
		log:            logger,
		pool:           make(map[wgdevice.NoisePublicKey]*peerEndpoints),
		bind:           bind,
		updateInterval: updateInterval,
		requestTimeout: 5 * time.Second,
		ctx:            ctx,
		cancel:         cancel,
	}
}

// Clear implements EndpointPool.
func (e *endpointPool) Clear() {
	panic("unimplemented")
}

// Close implements EndpointPool.
func (e *endpointPool) Close() {
	e.cancel()
	e.wg.Wait()
}

func (e *endpointPool) GetAllEndpoints(key wgdevice.NoisePublicKey) []conn.Endpoint {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if peer, exists := e.pool[key]; exists {
		peer.mu.RLock()
		defer peer.mu.RUnlock()
		return append([]conn.Endpoint(nil), peer.eps...)
	}
	return nil
}

// AddPeer adds a new peer and starts periodic endpoint updates
func (e *endpointPool) AddPeer(key wgdevice.NoisePublicKey) {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Check if peer already exists
	if _, exists := e.pool[key]; exists {
		e.log.Verbosef("Peer %x already exists in endpoint pool", key[:8])
		return
	}

	ctx, cancel := context.WithCancel(e.ctx)
	peer := &peerEndpoints{
		cancel: cancel,
	}
	e.pool[key] = peer

	// Start update goroutine for this peer
	e.wg.Add(1)
	go e.updatePeerLoop(ctx, peer, key)

	e.log.Verbosef("Added peer %x to endpoint pool", key[:8])
}

// RemovePeer removes a peer from the pool
func (e *endpointPool) RemovePeer(key wgdevice.NoisePublicKey) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if _, exists := e.pool[key]; exists {
		delete(e.pool, key)
		e.log.Verbosef("Removed peer %x from endpoint pool", key[:8])
	}
}

// updatePeerLoop runs in a goroutine to periodically update peer endpoints
func (e *endpointPool) updatePeerLoop(ctx context.Context, p *peerEndpoints, key wgdevice.NoisePublicKey) {
	defer e.wg.Done()

	ticker := time.NewTicker(e.updateInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			e.log.Verbosef("Stopping endpoint updates for peer %x", key)
			return
		case <-ticker.C:
			// response, err := e.client.RequestEndpoints(ctx, key, e.requestTimeout)
			// if err != nil {
			// 	e.log.Verbosef("Error RequestEndpoints %x", key[:8])
			// 	continue
			// }
			// var newEndpoints []conn.Endpoint
			// for _, ep := range response.Endpoints {
			// 	endpointStr := fmt.Sprintf("%s:%d", net.IP(ep.Ip), ep.Port)
			// 	connEndpoint, err := e.bind.ParseEndpoint(endpointStr)
			// 	if err != nil {
			// 		e.log.Errorf("Failed to parse endpoint %s: %v", endpointStr, err)
			// 		continue
			// 	}
			// 	newEndpoints = append(newEndpoints, connEndpoint)
			// }
			// p.mu.Lock()
			// p.eps = newEndpoints
			// p.mu.Unlock()
		}
	}
}
