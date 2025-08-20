package endpointpool

import (
	"context"
	"crypto/rand"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/bajacc/tinescale/pkg/stunPool"
	"github.com/bajacc/tinescale/pkg/tun"
	"golang.zx2c4.com/wireguard/conn"
	wgdevice "golang.zx2c4.com/wireguard/device"
)

type endpoint struct {
	origPubKey wgdevice.NoisePublicKey
}

func NewEndpoint(pubKey wgdevice.NoisePublicKey) *endpoint {
	return &endpoint{
		origPubKey: pubKey,
	}
}

// ClearSrc implements conn.Endpoint.
func (e *endpoint) ClearSrc() {}

// DstIP implements conn.Endpoint.
func (e *endpoint) DstIP() netip.Addr {
	// TODO do we need that?
	// Generate a deterministic IP from the public key for rate limiting
	// Use the first 4 bytes of the public key as an IPv4 address in the 10.0.0.0/8 range
	if len(e.origPubKey) >= 4 {
		return netip.AddrFrom4([4]byte{10, e.origPubKey[0], e.origPubKey[1], e.origPubKey[2]})
	}
	return netip.Addr{}
}

// DstToBytes implements conn.Endpoint.
func (e *endpoint) DstToBytes() []byte {
	return e.origPubKey[:]
}

// DstToString implements conn.Endpoint.
func (e *endpoint) DstToString() string {
	return fmt.Sprintf("tinescale:%x", e.origPubKey[:8])
}

// SrcIP implements conn.Endpoint.
func (e *endpoint) SrcIP() netip.Addr {
	return netip.Addr{}
}

// SrcToString implements conn.Endpoint.
func (e *endpoint) SrcToString() string {
	return ""
}

type EndpointPool interface {
	ClearPeers()
	Close()

	GetAllEndpoints(pubKey wgdevice.NoisePublicKey) []conn.Endpoint
	AddPeer(key wgdevice.NoisePublicKey)
	RemovePeer(key wgdevice.NoisePublicKey)
	SetListenPort(listenPort uint16)
	SetUAPIEndpoint(key wgdevice.NoisePublicKey, ep conn.Endpoint)
	GetRecv(recv conn.ReceiveFunc) conn.ReceiveFunc
	Send(bufs [][]byte, ep conn.Endpoint) error
	ReceiveChannel() <-chan ReceivedPacket
}

type endpointPool struct {
	log        *wgdevice.Logger
	mu         sync.RWMutex
	pool       map[wgdevice.NoisePublicKey]*peerEndpoints
	dstToKey   map[string]wgdevice.NoisePublicKey
	stunPool   stunPool.StunPool
	listenPort uint16
	bind       conn.Bind

	conn           tun.PubKeyConn
	updateInterval time.Duration
	requestTimeout time.Duration
	receivedCh     chan ReceivedPacket
	receivedPong   chan struct {
		key wgdevice.NoisePublicKey
		id  [4]byte
	}

	ctx       context.Context
	cancel    context.CancelFunc
	isWgRelay bool
}

type ReceivedPacket interface {
	Source() wgdevice.NoisePublicKey
	Data() []byte
}

type receivedPacket struct {
	source wgdevice.NoisePublicKey
	data   []byte
}

func (p *receivedPacket) Source() wgdevice.NoisePublicKey {
	return p.source
}

func (p *receivedPacket) Data() []byte {
	return p.data
}

type RelayMode int

const (
	RelayOff RelayMode = iota
	RelayIngress
	RelayEgress
	RelayOn
)

func (c *pathCandidate) Send(bufs [][]byte) error {
	// TODO
	if c.Type == PathUAPI {
		return c.Endpoint.Send(bufs)
	} else if c.Type == PathSTUN {
		return c.Endpoint.Send(bufs)
	} else if c.Type == PathRelay {
		return c.Endpoint.Send(bufs)
	}
	return fmt.Errorf("unknown path type: %d", c.Type)
}

func sendPing(id [4]byte, c PathCandidate) error {
	var pingMsg [5]byte
	pingMsg[0] = 0x05
	copy(pingMsg[1:5], id[:])
	return c.Send([][]byte{pingMsg[:]})
}

type PathType int

const (
	PathUAPI PathType = iota
	PathSTUN
	PathRelay
)

type pathCandidate struct {
	Type     PathType
	Endpoint conn.Endpoint
	pingSent time.Time
	pingId   [4]byte
	rtt      time.Duration
	Lastseen time.Time
}

type peerEndpoints struct {
	mu            sync.RWMutex
	stunEndpoints []conn.Endpoint
	uapiEndpoint  conn.Endpoint
	relayMode     RelayMode

	pathCandidates     map[string]*pathCandidate
	bestPathCandiateId string
}

func (e *endpointPool) GetRecv(recv conn.ReceiveFunc) conn.ReceiveFunc {
	return func(bufs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		n, err := recv(bufs, sizes, eps)
		if err != nil {
			return n, err
		}

		lastPos := 0
		for i := 0; i < n; i++ {
			if bufs[i] == nil || sizes[i] == 0 {
				continue
			}
			switch bufs[i][0] {
			case 0x05: // Ping message
				// TODO process ping
				if sizes[i] < 5 {
					return n, fmt.Errorf("invalid ping message length: %d", len(bufs[i]))
				}
				bufs[i][0] = 0x06 // Change to Pong message
				e.bind.Send([][]byte{bufs[i][1:5]}, eps[i])
				continue
			case 0x06: // Pong message
				if sizes[i] < 5 {
					return n, fmt.Errorf("invalid pong message length: %d", len(bufs[i]))
				}
				// TODO process pong
				bufs[lastPos] = bufs[i]
				key, exists := e.dstToKey[eps[i].DstToString()]
				if !exists {
					return n, fmt.Errorf("no tinescale endpoint found for %s", eps[i].DstToString())
				}
				e.receivedPong <- struct {
					key   wgdevice.NoisePublicKey
					nonce [4]byte
				}{
					key:   key,
					nonce: [4]byte{bufs[i][1], bufs[i][2], bufs[i][3], bufs[i][4]},
				}
				continue
			default:
				bufs[lastPos] = bufs[i]
				key, exists := e.dstToKey[eps[i].DstToString()]
				if !exists {
					return n, fmt.Errorf("no tinescale endpoint found for %s", eps[i].DstToString())
				}
				eps[lastPos] = NewEndpoint(key)
				sizes[lastPos] = sizes[i]
				lastPos += 1
			}
		}
		return lastPos, nil
	}
}

func (e *endpointPool) pingAllEndpointCandidateLoop() {
	ticker := time.NewTicker(e.updateInterval)
	defer ticker.Stop()
	for {
		select {
		case <-e.ctx.Done():
			return
		case <-ticker.C:
			e.mu.RLock()
			for key, peer := range e.pool {
				e.pingAllEndpointCandidate(key, peer)
			}
			e.mu.RUnlock()
		case s := <-e.receivedPong:
			e.mu.RLock()
			peer, ok := e.pool[s.key]
			e.mu.RUnlock()
			if !ok {
				e.log.Errorf("Received pong for unknown peer %x", s.key[:8])
				continue
			}
			peer.mu.RLock()
			for _, candidate := range peer.pathCandidates {
				if candidate == nil || candidate.nonce != s.nonce {
					continue
				}
				candidate.rtt = time.Since(candidate.pingSent)
			}
			peer.mu.RUnlock()
		}
	}
}

func createPingMessage() ([5]byte, error) {
	var pingMsg [5]byte
	pingMsg[0] = 0x05
	_, err := rand.Read(pingMsg[1:5])
	return pingMsg, err
}

func (e *endpointPool) pingAllEndpointCandidate(key wgdevice.NoisePublicKey, peer *peerEndpoints) {
	peer.mu.RLock()
	defer peer.mu.RUnlock()
	for _, candidate := range peer.pathCandidates {
		if candidate == nil {
			continue
		}
		var nonce [4]byte
		if _, err := rand.Read(candidate.nonce); err != nil {
			e.log.Errorf("Failed to generate nonce for ping: %v", err)
			continue
		}
		// TODO
		candidate.pingSent = time.Now()
		if err := sendPing(nonce, candidate); err != nil {
			e.log.Errorf("Failed to send ping to endpoint %s: %v", candidate.DstToString(), err)
			continue
		}
	}
}

func New(logger *wgdevice.Logger, conn tun.PubKeyConn, bind conn.Bind, stunPool stunPool.StunPool, updateInterval time.Duration) EndpointPool {
	ctx, cancel := context.WithCancel(context.Background())

	e := &endpointPool{
		log:            logger,
		pool:           make(map[wgdevice.NoisePublicKey]*peerEndpoints),
		stunPool:       stunPool,
		conn:           conn,
		bind:           bind,
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

	conn.SetFromRelayMessageHandler(func(src, dst wgdevice.NoisePublicKey, msg *tun.FromRelayMessage) error {
		e.mu.RLock()
		peer, ok := e.pool[src]
		e.mu.RUnlock()

		if !ok {
			e.log.Verbosef("Received message from unknown peer %x", src[:8])
			return nil
		}

		peer.mu.RLock()
		mode := peer.relayMode
		peer.mu.RUnlock()

		if ok && (mode == RelayOn || mode == RelayIngress) {

			// TODO process ping message
			e.receivedCh <- &receivedPacket{
				source: wgdevice.NoisePublicKey(msg.SrcKey),
				data:   msg.Data,
			}
		}
		return nil
	})

	conn.SetToRelayMessageHandler(func(src, dst wgdevice.NoisePublicKey, msg *tun.ToRelayMessage) error {
		e.mu.RLock()

		if !e.isWgRelay {
			e.mu.RUnlock()
			return nil
		}

		e.mu.RUnlock()

		fromRelay := &tun.FromRelayMessage{
			SrcKey: msg.SrcKey,
			DstKey: msg.DstKey,
			Data:   msg.Data,
		}
		return conn.SendFromRelayMessage(wgdevice.NoisePublicKey(msg.DstKey), fromRelay)
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
	result = append(result, peer.stunEndpoints...)
	if peer.uapiEndpoint != nil {
		result = append(result, peer.uapiEndpoint)
	}
	return result
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
		connEndpoint, err := e.bind.ParseEndpoint(endpointStr)
		if err != nil {
			e.log.Errorf("Failed to parse endpoint %s: %v", endpointStr, err)
			continue
		}
		newEndpoints = append(newEndpoints, connEndpoint)
	}

	peer.mu.Lock()
	e.log.Verbosef("received new endpoint: %v", newEndpoints)
	peer.stunEndpoints = newEndpoints
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

func (e *endpointPool) Send(bufs [][]byte, connEp conn.Endpoint) error {
	ep, ok := connEp.(*endpoint)
	if !ok {
		return fmt.Errorf("Error Enpoint is not a tinescale endpoint")
	}

	e.mu.RLock()
	peer, exists := e.pool[ep.origPubKey]
	e.mu.RUnlock()
	if !exists {
		return fmt.Errorf("no peer found for endpoint %s", ep.DstToString())
	}

	peer.mu.RLock()
	defer peer.mu.RUnlock()
	candidate, exists := peer.pathCandidates[/*TODO */ ]
	if !exists {
		return fmt.Errorf("no path candidate found for endpoint %s", ep.DstToString())
	}
	return candidate.Send(bufs)
}
