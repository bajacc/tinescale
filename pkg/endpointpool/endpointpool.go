package endpointpool

import (
	"context"
	"crypto/rand"
	"fmt"
	mathrand "math/rand"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/bajacc/tinescale/pkg/securemsg"
	"github.com/bajacc/tinescale/pkg/stunPool"
	"golang.zx2c4.com/wireguard/conn"
	wgdevice "golang.zx2c4.com/wireguard/device"
	"google.golang.org/protobuf/proto"
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

	AddPeer(key wgdevice.NoisePublicKey)
	RemovePeer(key wgdevice.NoisePublicKey)
	SetListenPort(listenPort uint16)
	SetUAPIEndpoint(key wgdevice.NoisePublicKey, ep conn.Endpoint)
	GetRecv(recv conn.ReceiveFunc) conn.ReceiveFunc
	SendBest(bufs [][]byte, ep conn.Endpoint) error
	ReceiveChannel() <-chan ReceivedPacket
}

type endpointPool struct {
	log                *wgdevice.Logger
	mu                 sync.RWMutex
	pool               map[wgdevice.NoisePublicKey]*peerEndpoints
	dstToPathCandidate map[string]*pathCandidate
	stunPool           stunPool.StunPool
	listenPort         uint16
	bind               conn.Bind
	localKey           wgdevice.NoisePrivateKey

	updateInterval time.Duration
	requestTimeout time.Duration
	receivedCh     chan ReceivedPacket

	ctx       context.Context
	cancel    context.CancelFunc
	isWgRelay bool
	securemsg securemsg.SecureMsg
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

func (e *endpointPool) Send(bufs [][]byte, path *pathCandidate) error {
	path.mu.RLock()
	defer path.mu.RUnlock()

	switch path.Type {
	case PathUAPI, PathSTUN:
		return e.bind.Send(bufs, path.Endpoint)
	case PathRelayUDP:
		var toRelayMessages [][]byte
		for _, data := range bufs {
			toRelayMessage := securemsg.ToRelayMessage{
				SrcKey: e.localKey[:],
				DstKey: path.Key[:],
				Data:   data,
			}
			buf, err := proto.Marshal(&toRelayMessage)
			if err != nil {
				return fmt.Errorf("failed to marshal ToRelayMessage: %w", err)
			}
			toRelayMessages = append(toRelayMessages, buf)
		}
		return e.bind.Send(toRelayMessages, path.Endpoint)
	default:
		return fmt.Errorf("unknown path type: %d", path.Type)
	}
}

type PathType int

const (
	PathUAPI PathType = iota
	PathSTUN
	PathRelayUDP
)

type pathCandidate struct {
	mu       sync.RWMutex
	Type     PathType
	Key      wgdevice.NoisePublicKey
	Endpoint conn.Endpoint

	PingSent time.Time
	PingId   [4]byte
	Rtt      time.Duration
	Lastseen time.Time
}

type peerEndpoints struct {
	uapiPathId string
	stunPathId []string

	mu        sync.RWMutex
	relayMode RelayMode

	pathCandidates map[string]*pathCandidate
	bestPath       string
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
			path, exists := e.dstToPathCandidate[eps[i].DstToString()]
			if !exists {
				return n, fmt.Errorf("no tinescale endpoint found for %s", eps[i].DstToString())
			}
			switch bufs[i][0] {
			case 0x05, 0x06, 0x07:
				if err := e.processTinescaleMessage(bufs[i][0], bufs[i][4:sizes[i]], path); err != nil {
					return n, err
				}
			default:
				bufs[lastPos] = bufs[i]
				eps[lastPos] = NewEndpoint(path.Key)
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
			for _, peer := range e.pool {
				e.pingAllEndpointCandidate(peer)
			}
			e.mu.RUnlock()
		}
	}
}

func (e *endpointPool) pingAllEndpointCandidate(peer *peerEndpoints) {
	peer.mu.RLock()
	defer peer.mu.RUnlock()
	for _, candidate := range peer.pathCandidates {
		if candidate == nil {
			continue
		}
		if _, err := rand.Read(candidate.PingId[:]); err != nil {
			e.log.Errorf("Failed to generate nonce for ping: %v", err)
			continue
		}
		candidate.PingSent = time.Now()

		var nonce [4]byte
		rand.Read(nonce[:])
		ping, err := e.securemsg.CreatePingMessage(nonce)
		if err != nil {
			e.log.Errorf("Failed to create ping message: %v", err)
			continue
		}

		// Prepend handshake response message type
		responseMsg := make([]byte, 4+len(ping))
		responseMsg[0] = 0x07 // Handshake Transport message type
		copy(responseMsg[4:], ping)
		if err := e.Send([][]byte{responseMsg}, candidate); err != nil {
			e.log.Errorf("Failed to send ping: %v", err)
		}
	}
}

func New(logger *wgdevice.Logger, bind conn.Bind, stunPool stunPool.StunPool, updateInterval time.Duration) EndpointPool {
	ctx, cancel := context.WithCancel(context.Background())

	e := &endpointPool{
		log:                logger,
		pool:               make(map[wgdevice.NoisePublicKey]*peerEndpoints),
		dstToPathCandidate: make(map[string]*pathCandidate),
		stunPool:           stunPool,
		bind:               bind,
		updateInterval:     updateInterval,
		requestTimeout:     5 * time.Second,
		receivedCh:         make(chan ReceivedPacket, 1024),
		ctx:                ctx,
		cancel:             cancel,
	}

	go e.updateEndpointLoop(ctx)
	go e.pingAllEndpointCandidateLoop()

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
	delete(peer.pathCandidates, peer.uapiPathId)
	delete(e.dstToPathCandidate, peer.uapiPathId)
	peer.uapiPathId = ep.DstToString()
	peer.pathCandidates[peer.uapiPathId] = &pathCandidate{
		Type:     PathUAPI,
		Key:      key,
		Endpoint: ep,
	}
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
	e.pool[key] = &peerEndpoints{
		pathCandidates: make(map[string]*pathCandidate),
	}

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
				msg := &securemsg.UnencryptedMessage{
					MessageType: &securemsg.UnencryptedMessage_EndpointRequest{
						EndpointRequest: &securemsg.EndpointRequest{
							RequestId: uint32(mathrand.Int31()),
						},
					},
				}
				buf, err := e.securemsg.EncryptNoiseTransport(msg, key)
				if err != nil {
					e.log.Verbosef("Failed to encrypt endpoint request: %v", err)
					continue
				}
				e.SendBest([][]byte{buf}, NewEndpoint(key))
			}
			e.mu.RUnlock()
		}
	}
}

// processEndpointResponse processes an endpoint response and updates the peer's endpoints
func (e *endpointPool) handleEndpointResponse(response *securemsg.EndpointResponse, path *pathCandidate) error {

	newPaths := make(map[string]*pathCandidate)
	for _, addr := range response.Addresses {
		endpointStr := fmt.Sprintf("%s:%d", net.IP(addr.Ip), addr.Port)
		connEndpoint, err := e.bind.ParseEndpoint(endpointStr)
		if err != nil {
			e.log.Errorf("Failed to parse endpoint %s: %v", endpointStr, err)
			continue
		}
		newPaths[connEndpoint.DstToString()] = &pathCandidate{
			Type:     PathSTUN,
			Key:      path.Key,
			Endpoint: connEndpoint,
		}
	}

	e.mu.RLock()
	peer, exists := e.pool[path.Key]
	if !exists {
		e.mu.RUnlock()
		return fmt.Errorf("endpoint response peer not found")
	}

	peer.mu.Lock()
	for _, pathId := range peer.stunPathId {
		delete(peer.pathCandidates, pathId)
		delete(e.dstToPathCandidate, pathId)
	}
	peer.stunPathId = nil
	for pathId, newPath := range newPaths {
		peer.pathCandidates[pathId] = newPath
		e.dstToPathCandidate[pathId] = newPath
		peer.stunPathId = append(peer.stunPathId, pathId)
	}
	peer.mu.Unlock()
	e.mu.RUnlock()
	return nil
}

// handleEndpointRequest processes incoming endpoint requests and sends a response
func (e *endpointPool) handleEndpointRequest(request *securemsg.EndpointRequest, path *pathCandidate) error {

	localEndpoints := e.getLocalEndpoints()
	e.log.Verbosef("local endpoints to be sent %v", localEndpoints)
	msg := &securemsg.UnencryptedMessage{
		MessageType: &securemsg.UnencryptedMessage_EndpointResponse{
			EndpointResponse: &securemsg.EndpointResponse{
				RequestId: request.RequestId,
				Addresses: localEndpoints,
			},
		},
	}

	buf, err := e.securemsg.EncryptNoiseTransport(msg, path.Key)
	if err != nil {
		e.log.Errorf("Failed to encrypt endpoint response: %v", err)
	}

	return e.Send([][]byte{buf}, path)
}

// getLocalEndpoints returns the local endpoints that can be shared with peers
func (e *endpointPool) getLocalEndpoints() []*securemsg.Address {
	var result []*securemsg.Address

	// Get STUN-discovered public endpoints
	stunResults := e.stunPool.GetAllResults()
	for _, stunResult := range stunResults {
		result = append(result, &securemsg.Address{
			Ip:   stunResult.PublicIP,
			Port: uint32(stunResult.PublicPort),
		})
		result = append(result, &securemsg.Address{
			Ip:   stunResult.LocalIP,
			Port: uint32(e.listenPort),
		})
	}
	return result
}

func (e *endpointPool) processUnencryptedMessage(msg *securemsg.UnencryptedMessage, path *pathCandidate) {
	if msg == nil {
		return
	}

	switch msgType := msg.GetMessageType().(type) {
	case *securemsg.UnencryptedMessage_PingMessage:
		e.handlePingMessage(msgType.PingMessage, path)
	case *securemsg.UnencryptedMessage_PongMessage:
		e.handlePongMessage(msgType.PongMessage, path)
	case *securemsg.UnencryptedMessage_EndpointRequest:
		e.handleEndpointRequest(msgType.EndpointRequest, path)
	case *securemsg.UnencryptedMessage_EndpointResponse:
		e.handleEndpointResponse(msgType.EndpointResponse, path)
	case *securemsg.UnencryptedMessage_ToRelay:
		e.handleToRelayMessage(msgType.ToRelay, path)
	case *securemsg.UnencryptedMessage_FromRelay:
		e.handleFromRelayMessage(msgType.FromRelay, path)
	default:
		e.log.Errorf("Unknown message type in unencrypted message from %v", path)
	}
}

func (e *endpointPool) handleFromRelayMessage(msg *securemsg.FromRelayMessage, path *pathCandidate) {
	e.mu.RLock()
	peer, ok := e.pool[wgdevice.NoisePublicKey(msg.DstKey)]
	e.mu.RUnlock()

	if !ok {
		e.log.Verbosef("Received message from unknown peer %x", msg.DstKey)
		return
	}

	peer.mu.RLock()
	mode := peer.relayMode
	peer.mu.RUnlock()

	if mode == RelayOff || mode == RelayEgress {
		return
	}

	switch msg.Data[0] {
	case 0x05, 0x06, 0x07:
		e.processTinescaleMessage(msg.Data[0], msg.Data[4:], path)
	default:
		e.receivedCh <- &receivedPacket{
			source: wgdevice.NoisePublicKey(msg.SrcKey),
			data:   msg.Data,
		}
	}
}

func (e *endpointPool) processTinescaleMessage(message_type byte, buf []byte, path *pathCandidate) error {
	switch message_type {
	case 0x05: // Handshake Init message
		response, err := e.securemsg.HandleNoiseInit(buf)
		if err != nil {
			return err
		}
		// Prepend handshake response message type
		responseMsg := make([]byte, 4+len(response))
		responseMsg[0] = 0x06 // Handshake Response message type
		copy(responseMsg[4:], response)
		if err := e.Send([][]byte{responseMsg}, path); err != nil {
			return fmt.Errorf("failed to send handshake response: %v", err)
		}
	case 0x06: // Handshake Response message
		if err := e.securemsg.HandleNoiseResponse(buf); err != nil {
			return fmt.Errorf("failed to handle noise response: %v", err)
		}
	case 0x07: // tinescale Transport message
		msg, err := e.securemsg.DecryptNoiseTransport(buf)
		if err != nil {
			return fmt.Errorf("failed to decrypt transport message: %v", err)
		}
		e.processUnencryptedMessage(msg, path)
	}
	return nil
}

func (e *endpointPool) handleToRelayMessage(relay *securemsg.ToRelayMessage, path *pathCandidate) {
	e.mu.RLock()

	if !e.isWgRelay {
		e.mu.RUnlock()
		return
	}

	e.mu.RUnlock()

	msg := &securemsg.UnencryptedMessage{
		MessageType: &securemsg.UnencryptedMessage_FromRelay{
			FromRelay: &securemsg.FromRelayMessage{
				SrcKey: relay.SrcKey,
				DstKey: relay.DstKey,
				Data:   relay.Data,
			},
		},
	}
	buf, err := e.securemsg.EncryptNoiseTransport(msg, path.Key)
	if err != nil {
		e.log.Errorf("Failed to encrypt from relay message: %v", err)
		return
	}
	e.Send([][]byte{buf}, path)
}

func (e *endpointPool) handlePingMessage(ping *securemsg.PingMessage, path *pathCandidate) {
	if ping == nil {
		return
	}

	e.log.Verbosef("Received ping with nonce %d", ping.Nonce)

	pong := &securemsg.UnencryptedMessage{
		MessageType: &securemsg.UnencryptedMessage_PongMessage{
			PongMessage: &securemsg.PongMessage{
				Nonce: ping.Nonce,
			},
		},
	}

	// Encrypt and send pong
	encryptedPong, err := e.securemsg.EncryptNoiseTransport(pong, path.Key)
	if err != nil {
		e.log.Errorf("Failed to encrypt pong message: %v", err)
		return
	}

	// Prepend transport message type
	transportMsg := make([]byte, 4+len(encryptedPong))
	transportMsg[0] = 0x07 // Transport message type
	copy(transportMsg[4:], encryptedPong)

	if err := e.Send([][]byte{transportMsg}, path); err != nil {
		e.log.Errorf("Failed to send pong message: %v", err)
	}
}

func (e *endpointPool) handlePongMessage(pong *securemsg.PongMessage, path *pathCandidate) {

	// Convert nonce to [4]byte format
	var nonceBytes [4]byte
	nonceBytes[0] = byte(pong.Nonce)
	nonceBytes[1] = byte(pong.Nonce >> 8)
	nonceBytes[2] = byte(pong.Nonce >> 16)
	nonceBytes[3] = byte(pong.Nonce >> 24)

	path.mu.Lock()
	defer path.mu.Unlock()
	if path.PingId == nonceBytes {
		path.Rtt = time.Since(path.PingSent)
		path.Lastseen = time.Now()
	}
}

func (e *endpointPool) SendBest(bufs [][]byte, connEp conn.Endpoint) error {
	ep, ok := connEp.(*endpoint)
	if !ok {
		return fmt.Errorf("error enpoint is not a tinescale endpoint")
	}

	e.mu.RLock()
	peer, exists := e.pool[ep.origPubKey]
	e.mu.RUnlock()
	if !exists {
		return fmt.Errorf("no peer found for endpoint %s", ep.DstToString())
	}

	peer.mu.RLock()
	defer peer.mu.RUnlock()

	// Use best path candidate if available
	if peer.bestPath != "" {
		if candidate, exists := peer.pathCandidates[peer.bestPath]; exists {
			return e.Send(bufs, candidate)
		}
	}

	// Fallback to any available candidate
	for _, candidate := range peer.pathCandidates {
		if candidate != nil {
			return e.Send(bufs, candidate)
		}
	}

	return fmt.Errorf("no path candidate available for endpoint %s", ep.DstToString())
}

func (e *endpointPool) ReceiveChannel() <-chan ReceivedPacket {
	return e.receivedCh
}
