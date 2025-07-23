//go:generate protoc --go_out=paths=source_relative:. endpointpool.proto
package endpointpool

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"sync"
	"time"

	"github.com/bajacc/tinescale/pkg/tun"
	"golang.zx2c4.com/wireguard/conn"
	wgdevice "golang.zx2c4.com/wireguard/device"
	"google.golang.org/protobuf/proto"
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
	pool map[wgdevice.NoisePublicKey]*peerEndpoints

	tun            *tun.InterceptTun
	bind           conn.Bind
	updateInterval time.Duration
	requestTimeout time.Duration
	ctx            context.Context
	cancel         context.CancelFunc
}

type peerEndpoints struct {
	mu  sync.RWMutex
	eps []conn.Endpoint
}

func New(logger *wgdevice.Logger, tun *tun.InterceptTun, bind conn.Bind, updateInterval time.Duration) EndpointPool {
	ctx, cancel := context.WithCancel(context.Background())

	e := &endpointPool{
		log:            logger,
		pool:           make(map[wgdevice.NoisePublicKey]*peerEndpoints),
		tun:            tun,
		bind:           bind,
		updateInterval: updateInterval,
		requestTimeout: 5 * time.Second,
		ctx:            ctx,
		cancel:         cancel,
	}

	go e.updateEndpointLoop(ctx)
	go e.handleIncomingResponses(ctx)

	return e
}

// Clear implements EndpointPool.
func (e *endpointPool) Clear() {
	panic("unimplemented")
}

// Close implements EndpointPool.
func (e *endpointPool) Close() {
	e.cancel()
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
	e.pool[key] = &peerEndpoints{}

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
func (e *endpointPool) updateEndpointLoop(ctx context.Context) {
	ticker := time.NewTicker(e.updateInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			e.log.Verbosef("Stopping endpoint updates")
			return
		case <-ticker.C:
			e.mu.RLock()
			for key := range e.pool {
				if err := e.requestEndpoints(key); err != nil {
					e.log.Verbosef("Error requesting endpoints from peer %x: %v", key[:8], err)
				}
			}
			e.mu.RUnlock()
		}
	}
}

// requestEndpoints sends a request for endpoints to a peer
func (e *endpointPool) requestEndpoints(peerKey wgdevice.NoisePublicKey) error {
	request := &EndpointRequest{
		RequestId: rand.Uint32(),
	}

	data, err := proto.Marshal(request)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	e.tun.SendPubKeyPacket(peerKey, data)
	e.log.Verbosef("Sent endpoint request to peer %x", peerKey[:8])
	return nil
}

// handleIncomingResponses processes incoming endpoint responses from peers
func (e *endpointPool) handleIncomingResponses(ctx context.Context) {
	inboundCh := e.tun.GetInboundPacket()

	for {
		select {
		case <-ctx.Done():
			return
		case packet, ok := <-inboundCh:
			if !ok {
				return
			}

			var response EndpointResponse
			if err := proto.Unmarshal(packet.Data(), &response); err != nil {
				e.log.Verbosef("Failed to unmarshal response from peer %x: %v", packet.Dst(), err)
				continue
			}

			e.processEndpointResponse(packet.Dst(), &response)
		}
	}
}

// processEndpointResponse processes an endpoint response and updates the peer's endpoints
func (e *endpointPool) processEndpointResponse(peerKey wgdevice.NoisePublicKey, response *EndpointResponse) {
	e.mu.RLock()
	peer, exists := e.pool[peerKey]
	e.mu.RUnlock()

	if !exists {
		e.log.Verbosef("Received response for unknown peer %x", peerKey[:8])
		return
	}

	var newEndpoints []conn.Endpoint
	for _, addr := range response.Addresses {
		endpointStr := fmt.Sprintf("%s:%d", net.IP(addr.Ip), addr.Port)
		connEndpoint, err := e.bind.ParseEndpoint(endpointStr)
		if err != nil {
			e.log.Errorf("Failed to parse endpoint %s: %v", endpointStr, err)
			continue
		}
		newEndpoints = append(newEndpoints, connEndpoint)
	}

	peer.mu.Lock()
	peer.eps = newEndpoints
	peer.mu.Unlock()

	e.log.Verbosef("Updated %d endpoints for peer %x", len(newEndpoints), peerKey)
}
