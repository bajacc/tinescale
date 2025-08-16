package endpointpool

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"sync"
	"time"

	"github.com/bajacc/tinescale/pkg/helper"
	"github.com/bajacc/tinescale/pkg/stunPool"
	"github.com/bajacc/tinescale/pkg/tun"
	"golang.zx2c4.com/wireguard/conn"
	wgdevice "golang.zx2c4.com/wireguard/device"
)

type EndpointPool interface {
	ClearPeers()
	Close()

	GetAllEndpoints(pubKey wgdevice.NoisePublicKey) []conn.Endpoint
	AddPeer(key wgdevice.NoisePublicKey)
	RemovePeer(key wgdevice.NoisePublicKey)
	SetListenPort(listenPort uint16)
	SetUAPIEndpoint(key wgdevice.NoisePublicKey, ep conn.Endpoint)
	FindKey(ep conn.Endpoint) (*wgdevice.NoisePublicKey, bool)
}

type endpointPool struct {
	log        *wgdevice.Logger
	mu         sync.RWMutex
	pool       map[wgdevice.NoisePublicKey]*peerEndpoints
	stunPool   stunPool.StunPool
	listenPort uint16

	conn           tun.PubKeyConn
	epParser       helper.EndpointParser
	updateInterval time.Duration
	requestTimeout time.Duration

	ctx    context.Context
	cancel context.CancelFunc
}

type peerEndpoints struct {
	mu           sync.RWMutex
	msgEndpoints []conn.Endpoint
	uapiEndpoint conn.Endpoint
}

func New(logger *wgdevice.Logger, conn tun.PubKeyConn, epParser helper.EndpointParser, stunPool stunPool.StunPool, updateInterval time.Duration) EndpointPool {
	ctx, cancel := context.WithCancel(context.Background())

	e := &endpointPool{
		log:            logger,
		pool:           make(map[wgdevice.NoisePublicKey]*peerEndpoints),
		stunPool:       stunPool,
		conn:           conn,
		epParser:       epParser,
		updateInterval: updateInterval,
		requestTimeout: 5 * time.Second,
		ctx:            ctx,
		cancel:         cancel,
	}

	conn.SetEndpointRequestHandler(func(src, dst wgdevice.NoisePublicKey, msg *tun.EndpointRequest) error {
		return e.handleEndpointRequest(src, msg)
	})

	conn.SetEndpointResponseHandler(func(src, dst wgdevice.NoisePublicKey, msg *tun.EndpointResponse) error {
		return e.handleEndpointResponse(src, msg)
	})

	go e.updateEndpointLoop(ctx)

	return e
}

// Clear implements EndpointPool.
func (e *endpointPool) ClearPeers() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.pool = make(map[wgdevice.NoisePublicKey]*peerEndpoints)
}

// Close implements EndpointPool.
func (e *endpointPool) Close() {
	e.cancel()
}

func (e *endpointPool) SetListenPort(listenPort uint16) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.listenPort = listenPort
}

func (e *endpointPool) SetUAPIEndpoint(key wgdevice.NoisePublicKey, ep conn.Endpoint) {
	if ep == nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()

	peer, exists := e.pool[key]
	if !exists {
		return
	}
	peer.mu.Lock()
	defer peer.mu.Unlock()
	peer.uapiEndpoint = ep
}

func (e *endpointPool) GetAllEndpoints(key wgdevice.NoisePublicKey) []conn.Endpoint {
	e.mu.RLock()
	defer e.mu.RUnlock()

	peer, exists := e.pool[key]
	if !exists {
		return nil
	}

	var result []conn.Endpoint
	peer.mu.RLock()
	defer peer.mu.RUnlock()
	result = append(result, peer.msgEndpoints...)
	if peer.uapiEndpoint != nil {
		result = append(result, peer.uapiEndpoint)
	}
	return result
}

func (e *endpointPool) FindKey(ep conn.Endpoint) (*wgdevice.NoisePublicKey, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	for key, peer := range e.pool {
		peer.mu.RLock()
		if peer.uapiEndpoint != nil && peer.uapiEndpoint.DstToString() == ep.DstToString() {
			peer.mu.RUnlock()
			return &key, true
		}
		for _, msgEp := range peer.msgEndpoints {
			if msgEp.DstToString() == ep.DstToString() {
				peer.mu.RUnlock()
				return &key, true
			}
		}
		peer.mu.RUnlock()
	}
	return nil, false
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

	e.log.Verbosef("update endpoint loop")
	for {
		select {
		case <-ctx.Done():
			e.log.Verbosef("Stopping endpoint updates")
			return
		case <-ticker.C:
			e.mu.RLock()
			e.log.Verbosef("send requestEndpoints")
			for key := range e.pool {
				request := &tun.EndpointRequest{
					RequestId: rand.Uint32(),
				}
				if err := e.conn.SendEndpointRequest(key, request); err != nil {
					e.log.Verbosef("Error requesting endpoints from peer %x: %v", key[:8], err)
				}
			}
			e.mu.RUnlock()
		}
	}
}

// processEndpointResponse processes an endpoint response and updates the peer's endpoints
func (e *endpointPool) handleEndpointResponse(peerKey wgdevice.NoisePublicKey, response *tun.EndpointResponse) error {
	e.mu.RLock()
	peer, exists := e.pool[peerKey]
	e.mu.RUnlock()

	if !exists {
		e.log.Verbosef("Received response for unknown peer %x", peerKey[:8])
		return nil
	}

	var newEndpoints []conn.Endpoint
	for _, addr := range response.Addresses {
		endpointStr := fmt.Sprintf("%s:%d", net.IP(addr.Ip), addr.Port)
		connEndpoint, err := e.epParser.ParseEndpoint(endpointStr)
		if err != nil {
			e.log.Errorf("Failed to parse endpoint %s: %v", endpointStr, err)
			continue
		}
		newEndpoints = append(newEndpoints, connEndpoint)
	}

	peer.mu.Lock()
	e.log.Verbosef("received new endpoint: %v", newEndpoints)
	peer.msgEndpoints = newEndpoints
	peer.mu.Unlock()
	return nil
}

// handleEndpointRequest processes incoming endpoint requests and sends a response
func (e *endpointPool) handleEndpointRequest(peerKey wgdevice.NoisePublicKey, request *tun.EndpointRequest) error {
	e.log.Verbosef("Received endpoint request from peer %x", peerKey)

	localEndpoints := e.getLocalEndpoints()
	e.log.Verbosef("local endpoints to be sent %v", localEndpoints)
	response := &tun.EndpointResponse{
		RequestId: request.RequestId,
		Addresses: localEndpoints,
	}

	return e.conn.SendEndpointResponse(peerKey, response)
}

// getLocalEndpoints returns the local endpoints that can be shared with peers
func (e *endpointPool) getLocalEndpoints() []*tun.Address {
	var result []*tun.Address

	// Get STUN-discovered public endpoints
	stunResults := e.stunPool.GetAllResults()
	for _, stunResult := range stunResults {
		result = append(result, &tun.Address{
			Ip:   stunResult.PublicIP,
			Port: uint32(stunResult.PublicPort),
		})
		result = append(result, &tun.Address{
			Ip:   stunResult.LocalIP,
			Port: uint32(e.listenPort),
		})
	}
	return result
}
