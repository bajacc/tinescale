//go:generate protoc --go_out=paths=source_relative:. endpointpool.proto
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
	"google.golang.org/protobuf/proto"
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

type PubKeyConn interface {
	GetInboundPacketCh() <-chan *tun.PubKeyPacket
	SendPubKeyPacket(dst wgdevice.NoisePublicKey, data []byte)
}

type endpointPool struct {
	log        *wgdevice.Logger
	mu         sync.RWMutex
	pool       map[wgdevice.NoisePublicKey]*peerEndpoints
	stunPool   stunPool.StunPool
	listenPort uint16

	tun            PubKeyConn
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

func New(logger *wgdevice.Logger, tun PubKeyConn, epParser helper.EndpointParser, stunPool stunPool.StunPool, updateInterval time.Duration) EndpointPool {
	ctx, cancel := context.WithCancel(context.Background())

	e := &endpointPool{
		log:            logger,
		pool:           make(map[wgdevice.NoisePublicKey]*peerEndpoints),
		stunPool:       stunPool,
		tun:            tun,
		epParser:       epParser,
		updateInterval: updateInterval,
		requestTimeout: 5 * time.Second,
		ctx:            ctx,
		cancel:         cancel,
	}

	go e.updateEndpointLoop(ctx)
	go e.handleIncomingPackets(ctx)

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
		if peer.uapiEndpoint.DstToString() == ep.DstToString() {
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
	wrapper := &MessageWrapper{
		MessageType: &MessageWrapper_EndpointRequest{
			EndpointRequest: request,
		},
	}

	data, err := proto.Marshal(wrapper)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	e.tun.SendPubKeyPacket(peerKey, data)
	return nil
}

// handleIncomingPackets processes incoming endpoint requests and responses from peers
func (e *endpointPool) handleIncomingPackets(ctx context.Context) {
	inboundCh := e.tun.GetInboundPacketCh()

	e.log.Verbosef("start handleIncomingPackets")
	for {
		select {
		case <-ctx.Done():
			e.log.Verbosef("endpointPool context canceled")
			return
		case packet, ok := <-inboundCh:
			if !ok {
				e.log.Verbosef("endpointPool: inboundCh channel closed")
				return
			}

			wrapper := &MessageWrapper{}
			if err := proto.Unmarshal(packet.Data(), wrapper); err != nil {
				e.log.Errorf("failed to unmarshal wrapper: %v", err)
				continue
			}
			e.log.Verbosef("received endpoint message")

			switch msg := wrapper.MessageType.(type) {
			case *MessageWrapper_EndpointRequest:
				e.handleEndpointRequest(packet.Src(), msg.EndpointRequest)
			case *MessageWrapper_EndpointResponse:
				e.processEndpointResponse(packet.Src(), msg.EndpointResponse)
			default:
				e.log.Verbosef("Failed to unmarshal packet from peer %x as request or response", packet.Src())
			}
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
}

// handleEndpointRequest processes incoming endpoint requests and sends a response
func (e *endpointPool) handleEndpointRequest(peerKey wgdevice.NoisePublicKey, request *EndpointRequest) {
	e.log.Verbosef("Received endpoint request from peer %x", peerKey)

	localEndpoints := e.getLocalEndpoints()
	response := &EndpointResponse{
		RequestId: request.RequestId,
		Addresses: localEndpoints,
	}
	wrapper := &MessageWrapper{
		MessageType: &MessageWrapper_EndpointResponse{
			EndpointResponse: response,
		},
	}
	data, err := proto.Marshal(wrapper)
	if err != nil {
		e.log.Errorf("Failed to marshal endpoint response: %v", err)
		return
	}

	e.tun.SendPubKeyPacket(peerKey, data)
}

func (e *endpointPool) getLocalEndpoints() []*Address {
	var result []*Address
	result = append(result, e.getPrivateEndpoints()...)
	result = append(result, e.getStunEndpoints()...)
	return result
}

// getLocalEndpoints returns the local endpoints that can be shared with peers
func (e *endpointPool) getStunEndpoints() []*Address {
	var result []*Address

	// Get STUN-discovered public endpoints
	stunResults := e.stunPool.GetAllResults()
	for _, stunResult := range stunResults {
		if stunResult.Err != nil {
			continue
		}
		result = append(result, &Address{
			Ip:   stunResult.PublicIP,
			Port: uint32(stunResult.PublicPort),
		})
	}
	return result
}

func (e *endpointPool) getPrivateEndpoints() []*Address {
	interfaces, err := net.Interfaces()
	if err != nil {
		return []*Address{}
	}
	var ifaceAddr []net.Addr
	for _, iface := range interfaces {
		// Skip loopback and down interfaces
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		ifaceAddr = append(ifaceAddr, addrs...)
	}

	var result []*Address
	for _, addr := range ifaceAddr {
		ipNet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		if !ipNet.IP.IsLoopback() && (ipNet.IP.IsGlobalUnicast() || ipNet.IP.IsPrivate()) {
			result = append(result, &Address{
				Ip:   ipNet.IP,
				Port: uint32(e.listenPort),
			})
		}
	}
	return result
}
