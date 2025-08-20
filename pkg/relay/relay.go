package relay

import (
	"sync"

	"github.com/bajacc/tinescale/pkg/tun"
	wgdevice "golang.zx2c4.com/wireguard/device"
)

type ReceivedPacket interface {
	Source() wgdevice.NoisePublicKey
	Data() []byte
}

type receivedPacket struct {
	source wgdevice.NoisePublicKey
	data   []byte
}

type Relay interface {
	ReceiveChannel() <-chan ReceivedPacket
	AddPeer(key wgdevice.NoisePublicKey)
	RemovePeer(key wgdevice.NoisePublicKey)
	ClearPeers()
	SetPeerRelayMode(key wgdevice.NoisePublicKey, mode RelayMode)
	SetWgRelay(isRelay bool)
	IsWgRelay() bool
	Send(bufs [][]byte, dst wgdevice.NoisePublicKey) error
	GetAllRelay() []wgdevice.NoisePublicKey
}

type RelayMode int

const (
	RelayOff RelayMode = iota
	RelayIngress
	RelayEgress
	RelayOn
)

type relay struct {
	log           *wgdevice.Logger
	mu            sync.RWMutex
	conn          tun.PubKeyConn
	relayCh       chan ReceivedPacket
	peerRelayMode map[wgdevice.NoisePublicKey]RelayMode
	isWgRelay     bool
}

func (r *relay) Send(bufs [][]byte, dst wgdevice.NoisePublicKey) error {
	relays := r.GetAllRelay()

	for _, data := range bufs {
		localKey := r.conn.LocalKey()
		toRelayMessage := &tun.ToRelayMessage{
			SrcKey: localKey[:],
			DstKey: dst[:],
			Data:   data,
		}
		for _, key := range relays {
			if key != dst && r.conn.SendToRelayMessage(key, toRelayMessage) == nil {
				break
			}
		}
	}
	return nil
}

func New(log *wgdevice.Logger, conn tun.PubKeyConn) Relay {
	r := &relay{
		log:       log,
		conn:      conn,
		relayCh:   make(chan ReceivedPacket, 1024),
		isWgRelay: false,
	}

	conn.SetFromRelayMessageHandler(func(src, dst wgdevice.NoisePublicKey, msg *tun.FromRelayMessage) error {
		r.mu.RLock()
		mode, ok := r.peerRelayMode[src]
		r.mu.RUnlock()

		if ok && (mode == RelayOn || mode == RelayIngress) {
			r.relayCh <- &receivedPacket{
				source: wgdevice.NoisePublicKey(msg.SrcKey),
				data:   msg.Data,
			}
		}
		return nil
	})

	conn.SetToRelayMessageHandler(func(src, dst wgdevice.NoisePublicKey, msg *tun.ToRelayMessage) error {
		r.mu.RLock()

		if !r.isWgRelay {
			r.mu.RUnlock()
			return nil
		}

		r.mu.RUnlock()

		fromRelay := &tun.FromRelayMessage{
			SrcKey: msg.SrcKey,
			DstKey: msg.DstKey,
			Data:   msg.Data,
		}
		return conn.SendFromRelayMessage(wgdevice.NoisePublicKey(msg.DstKey), fromRelay)
	})

	return r
}

func (p *receivedPacket) Source() wgdevice.NoisePublicKey {
	return p.source
}

func (p *receivedPacket) Data() []byte {
	return p.data
}

func (r *relay) GetAllRelay() []wgdevice.NoisePublicKey {
	r.mu.RLock()
	defer r.mu.RUnlock()

	keys := make([]wgdevice.NoisePublicKey, 0, len(r.peerRelayMode))
	for key := range r.peerRelayMode {
		if r.peerRelayMode[key] == RelayOn || r.peerRelayMode[key] == RelayEgress {
			keys = append(keys, key)
		}
	}
	return keys
}

func (r *relay) SetWgRelay(isRelay bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.isWgRelay = isRelay
}

func (r *relay) IsWgRelay() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.isWgRelay
}

func (r *relay) AddPeer(key wgdevice.NoisePublicKey) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.peerRelayMode[key] = RelayOff
}

func (r *relay) SetPeerRelayMode(key wgdevice.NoisePublicKey, mode RelayMode) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.peerRelayMode[key] = mode
}

func (r *relay) RemovePeer(key wgdevice.NoisePublicKey) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.peerRelayMode, key)
}

func (r *relay) ClearPeers() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.peerRelayMode = make(map[wgdevice.NoisePublicKey]RelayMode)
}

func (r *relay) ReceiveChannel() <-chan ReceivedPacket {
	return r.relayCh
}
