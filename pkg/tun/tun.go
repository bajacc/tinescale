//go:generate protoc --go_out=paths=source_relative:. tun.proto
package tun

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"

	"github.com/bajacc/tinescale/pkg/helper"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	wgdevice "golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"google.golang.org/protobuf/proto"
)

type EndpointRequestHandler func(src wgdevice.NoisePublicKey, dst wgdevice.NoisePublicKey, msg *EndpointRequest) error
type EndpointResponseHandler func(src wgdevice.NoisePublicKey, dst wgdevice.NoisePublicKey, msg *EndpointResponse) error
type ToRelayMessageHandler func(src wgdevice.NoisePublicKey, dst wgdevice.NoisePublicKey, msg *ToRelayMessage) error
type FromRelayMessageHandler func(src wgdevice.NoisePublicKey, dst wgdevice.NoisePublicKey, msg *FromRelayMessage) error

type PubKeyConn interface {
	SetEndpointRequestHandler(handler EndpointRequestHandler)
	SetEndpointResponseHandler(handler EndpointResponseHandler)
	SetToRelayMessageHandler(handler ToRelayMessageHandler)
	SetFromRelayMessageHandler(handler FromRelayMessageHandler)

	SendEndpointResponse(dst wgdevice.NoisePublicKey, msg *EndpointResponse) error
	SendEndpointRequest(dst wgdevice.NoisePublicKey, msg *EndpointRequest) error
	SendToRelayMessage(dst wgdevice.NoisePublicKey, msg *ToRelayMessage) error
	SendFromRelayMessage(dst wgdevice.NoisePublicKey, msg *FromRelayMessage) error
	LocalKey() wgdevice.NoisePublicKey
}

type InterceptTun struct {
	inner tun.Device
	log   *wgdevice.Logger

	localKey wgdevice.NoisePublicKey
	localNet netip.Prefix
	localIp  netip.Addr

	mu      sync.RWMutex
	ipToKey map[netip.Addr]wgdevice.NoisePublicKey

	endpointRequestHandler  EndpointRequestHandler
	endpointResponseHandler EndpointResponseHandler
	toRelayMessageHandler   ToRelayMessageHandler
	fromRelayMessageHandler FromRelayMessageHandler

	readCh     chan *readResult
	outboundCh chan *PubKeyPacket

	ctx    context.Context
	cancel context.CancelFunc
}

type readResult struct {
	bufs  [][]byte
	sizes []int
	n     int
	err   error
}

type PubKeyPacket struct {
	src  wgdevice.NoisePublicKey
	dst  wgdevice.NoisePublicKey
	data []byte
}

func (p *PubKeyPacket) Src() wgdevice.NoisePublicKey {
	return p.src
}

func (p *PubKeyPacket) Dst() wgdevice.NoisePublicKey {
	return p.dst
}

func (p *PubKeyPacket) Data() []byte {
	return p.data
}

func New(logger *wgdevice.Logger, tun tun.Device) *InterceptTun {
	ctx, cancel := context.WithCancel(context.Background())

	t := &InterceptTun{
		inner:      tun,
		log:        logger,
		localNet:   netip.MustParsePrefix("fd00::/8"),
		ipToKey:    make(map[netip.Addr]wgdevice.NoisePublicKey),
		readCh:     make(chan *readResult),
		outboundCh: make(chan *PubKeyPacket, 1024),
		ctx:        ctx,
		cancel:     cancel,
	}

	go t.routineReadFromTUN()

	return t
}

func (t *InterceptTun) SetLocalKey(localKey wgdevice.NoisePublicKey) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	localIp, ok := helper.PublicKeyToIP(t.localNet, localKey)
	if !ok {
		return fmt.Errorf("cannot convert %s to ip", localKey)
	}

	t.localKey = localKey
	t.localIp = localIp
	t.log.Verbosef("SetLocalKey %s %x", t.localIp, t.localKey)
	return nil
}

func (t *InterceptTun) LocalKey() wgdevice.NoisePublicKey {
	return t.localKey
}

func (t *InterceptTun) SetLocaNet(localNet netip.Prefix) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	localIp, ok := helper.PublicKeyToIP(localNet, t.localKey)
	if !ok {
		return fmt.Errorf("cannot convert %s to ip", t.localKey)
	}

	newIpToKey := make(map[netip.Addr]wgdevice.NoisePublicKey)
	for _, key := range t.ipToKey {
		ip, ok := helper.PublicKeyToIP(localNet, key)
		if !ok {
			return fmt.Errorf("cannot convert %s to ip", key)
		}
		newIpToKey[ip] = key
	}

	t.ipToKey = newIpToKey
	t.localNet = localNet
	t.localIp = localIp
	return nil
}

func (t *InterceptTun) SetEndpointRequestHandler(handler EndpointRequestHandler) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.endpointRequestHandler = handler
}

func (t *InterceptTun) SetEndpointResponseHandler(handler EndpointResponseHandler) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.endpointResponseHandler = handler
}

func (t *InterceptTun) SetToRelayMessageHandler(handler ToRelayMessageHandler) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.toRelayMessageHandler = handler
}

func (t *InterceptTun) SetFromRelayMessageHandler(handler FromRelayMessageHandler) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.fromRelayMessageHandler = handler
}

// BatchSize implements tun.Device.
func (t *InterceptTun) BatchSize() int {
	return t.inner.BatchSize()
}

// Close implements tun.Device.
func (t *InterceptTun) Close() error {
	t.cancel()
	close(t.outboundCh)
	return t.inner.Close()
}

// Events implements tun.Device.
func (t *InterceptTun) Events() <-chan tun.Event {
	return t.inner.Events()
}

// File implements tun.Device.
func (t *InterceptTun) File() *os.File {
	return t.inner.File()
}

// MTU implements tun.Device.
func (t *InterceptTun) MTU() (int, error) {
	return t.inner.MTU()
}

// Name implements tun.Device.
func (t *InterceptTun) Name() (string, error) {
	return t.inner.Name()
}

func (t *InterceptTun) AddPeer(key wgdevice.NoisePublicKey) error {
	ip, ok := t.PublicKeyToIP(key)
	if !ok {
		return fmt.Errorf("could not create ip from public key")
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	_, exists := t.ipToKey[ip]
	if exists {
		return fmt.Errorf("peer already exists")
	}
	t.ipToKey[ip] = key
	t.log.Verbosef("AddPeer %s %x", t.localIp, t.localKey)
	return nil
}

func (t *InterceptTun) PublicKeyToIP(key wgdevice.NoisePublicKey) (netip.Addr, bool) {
	return helper.PublicKeyToIP(t.localNet, key)
}

func (t *InterceptTun) RemovePeer(key wgdevice.NoisePublicKey) error {
	ip, ok := t.PublicKeyToIP(key)
	if !ok {
		return fmt.Errorf("could not create ip from public key")
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.ipToKey, ip)
	return nil
}

func (t *InterceptTun) ClearPeers() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.ipToKey = make(map[netip.Addr]wgdevice.NoisePublicKey)
}

func (t *InterceptTun) toIpPacket(ipPkt []byte, pkPkt *PubKeyPacket) (int, bool) {
	srcIP, ok1 := t.PublicKeyToIP(pkPkt.src)
	dstIP, ok2 := t.PublicKeyToIP(pkPkt.dst)
	if !ok1 || !ok2 {
		return 0, false
	}
	t.log.Verbosef("successful send %d %s %s", len(ipPkt), srcIP, dstIP)
	src := srcIP.AsSlice()
	dst := dstIP.AsSlice()
	if srcIP.Is4() {
		pktLen := len(pkPkt.data) + ipv4.HeaderLen
		ipPkt[0] = 0x45
		ipPkt[wgdevice.IPv4offsetTotalLength] = byte(pktLen >> 8)
		ipPkt[wgdevice.IPv4offsetTotalLength+1] = byte(pktLen & 0xFF)
		copy(ipPkt[wgdevice.IPv4offsetDst:wgdevice.IPv4offsetDst+net.IPv4len], dst)
		copy(ipPkt[wgdevice.IPv4offsetSrc:wgdevice.IPv4offsetSrc+net.IPv4len], src)
		copy(ipPkt[ipv4.HeaderLen:], pkPkt.data) // header length without extension headers
		return pktLen, true
	} else if srcIP.Is6() {
		payloadLen := len(pkPkt.data)
		ipPkt[0] = 0x60
		ipPkt[wgdevice.IPv6offsetPayloadLength] = byte(payloadLen >> 8)
		ipPkt[wgdevice.IPv6offsetPayloadLength+1] = byte(payloadLen & 0xFF)
		copy(ipPkt[wgdevice.IPv6offsetDst:wgdevice.IPv6offsetDst+net.IPv6len], dst)
		copy(ipPkt[wgdevice.IPv6offsetSrc:wgdevice.IPv6offsetSrc+net.IPv6len], src)
		copy(ipPkt[ipv6.HeaderLen:], pkPkt.data)
		return payloadLen + ipv6.HeaderLen, true
	}
	return 0, false
}

func (t *InterceptTun) toPubKeyPacket(ipPkt []byte) (*PubKeyPacket, bool) {
	if len(ipPkt) == 0 {
		return nil, false
	}

	var dst []byte
	var src []byte
	var headerLen int

	switch ipPkt[0] >> 4 {
	case 4:
		if len(ipPkt) < ipv4.HeaderLen {
			return nil, false
		}
		headerLen = ipv4.HeaderLen // header length without extension headers
		dst = ipPkt[wgdevice.IPv4offsetDst : wgdevice.IPv4offsetDst+net.IPv4len]
		src = ipPkt[wgdevice.IPv4offsetSrc : wgdevice.IPv4offsetSrc+net.IPv4len]
	case 6:
		if len(ipPkt) < ipv6.HeaderLen {
			return nil, false
		}
		headerLen = ipv6.HeaderLen
		dst = ipPkt[wgdevice.IPv6offsetDst : wgdevice.IPv6offsetDst+net.IPv6len]
		src = ipPkt[wgdevice.IPv6offsetSrc : wgdevice.IPv6offsetSrc+net.IPv6len]
	default:
		return nil, false
	}
	ipSrc, ok1 := netip.AddrFromSlice(src)
	ipDst, ok2 := netip.AddrFromSlice(dst)
	if !ok1 || !ok2 {
		return nil, false
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	if ipDst != t.localIp {
		return nil, false // only accept packet that have a local dst IP
	}
	keySrc, ok := t.ipToKey[ipSrc]
	if !ok {
		return nil, false
	}
	pkPkt := &PubKeyPacket{
		src:  keySrc,
		dst:  t.localKey,
		data: append([]byte(nil), ipPkt[headerLen:]...), // deep copy
	}
	return pkPkt, true
}

func (t *InterceptTun) sendMessageWrapper(dst wgdevice.NoisePublicKey, msg *MessageWrapper) error {
	data, err := proto.Marshal(msg)
	if err != nil {
		return err
	}
	t.outboundCh <- &PubKeyPacket{
		src:  t.localKey,
		dst:  dst,
		data: data,
	}
	return nil
}

func (t *InterceptTun) SendEndpointResponse(dst wgdevice.NoisePublicKey, msg *EndpointResponse) error {
	return t.sendMessageWrapper(dst, &MessageWrapper{
		MessageType: &MessageWrapper_EndpointResponse{
			EndpointResponse: msg,
		},
	})
}

func (t *InterceptTun) SendEndpointRequest(dst wgdevice.NoisePublicKey, msg *EndpointRequest) error {
	return t.sendMessageWrapper(dst, &MessageWrapper{
		MessageType: &MessageWrapper_EndpointRequest{
			EndpointRequest: msg,
		},
	})
}

func (t *InterceptTun) SendToRelayMessage(dst wgdevice.NoisePublicKey, msg *ToRelayMessage) error {
	return t.sendMessageWrapper(dst, &MessageWrapper{
		MessageType: &MessageWrapper_ToRelay{
			ToRelay: msg,
		},
	})
}

func (t *InterceptTun) SendFromRelayMessage(dst wgdevice.NoisePublicKey, msg *FromRelayMessage) error {
	return t.sendMessageWrapper(dst, &MessageWrapper{
		MessageType: &MessageWrapper_FromRelay{
			FromRelay: msg,
		},
	})
}

// Read implements tun.Device.
func (t *InterceptTun) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	for {
		select {
		case <-t.ctx.Done():
			return 0, net.ErrClosed
		case result, ok := <-t.readCh:
			if !ok {
				return 0, net.ErrClosed
			}
			if result.err != nil {
				return result.n, result.err
			}
			copy(sizes, result.sizes)
			for i := range result.n {
				copy(bufs[i][offset:], result.bufs[i][:sizes[i]])
			}
			return result.n, nil
		case packet, ok := <-t.outboundCh:
			if !ok {
				return 0, net.ErrClosed
			}

			if n, ok := t.toIpPacket(bufs[0][offset:], packet); ok {
				sizes[0] = n
				t.log.Verbosef("successful send %d %x %x", len(packet.data), packet.src, packet.dst)
				return 1, nil
			}
			continue // drop silently
		}
	}
}

func (t *InterceptTun) handleProtoMessage(pkg *PubKeyPacket) error {
	wrapper := &MessageWrapper{}
	if err := proto.Unmarshal(pkg.Data(), wrapper); err != nil {
		return err
	}
	t.log.Verbosef("received endpoint message")
	switch m := wrapper.MessageType.(type) {
	case *MessageWrapper_EndpointRequest:
		if t.endpointRequestHandler != nil {
			return t.endpointRequestHandler(pkg.Src(), pkg.Dst(), m.EndpointRequest)
		}
	case *MessageWrapper_EndpointResponse:
		if t.endpointRequestHandler != nil {
			return t.endpointResponseHandler(pkg.Src(), pkg.Dst(), m.EndpointResponse)
		}
	case *MessageWrapper_ToRelay:
		if t.toRelayMessageHandler != nil {
			return t.toRelayMessageHandler(pkg.Src(), pkg.Dst(), m.ToRelay)
		}
	case *MessageWrapper_FromRelay:
		if t.fromRelayMessageHandler != nil {
			return t.fromRelayMessageHandler(pkg.Src(), pkg.Dst(), m.FromRelay)
		}
	default:
		t.log.Errorf("unknown message type %T", wrapper.MessageType)
	}
	return nil
}

// Write implements tun.Device.
func (t *InterceptTun) Write(bufs [][]byte, offset int) (int, error) {
	var newBufs [][]byte
	write := 0
	for i := range bufs {
		packet := bufs[i][offset:]
		if pkPacket, ok := t.toPubKeyPacket(packet); ok {
			t.handleProtoMessage(pkPacket)
			write += 1
		} else {
			newBufs = append(newBufs, bufs[i])
		}
	}
	tunWrite, err := t.inner.Write(newBufs, offset)
	if err != nil {
		return 0, err
	}
	return tunWrite + write, nil
}

func (t *InterceptTun) routineReadFromTUN() {
	defer close(t.readCh)
	for {
		select {
		case <-t.ctx.Done():
			return
		default:
		}

		var (
			batchSize = t.inner.BatchSize()
			bufs      = make([][]byte, batchSize)
			sizes     = make([]int, batchSize)
		)

		for i := range bufs {
			bufs[i] = make([]byte, wgdevice.MaxMessageSize)
		}

		n, err := t.inner.Read(bufs, sizes, 0)
		t.readCh <- &readResult{
			bufs:  bufs,
			sizes: sizes,
			n:     n,
			err:   err,
		}
		if err == net.ErrClosed {
			return
		}
	}
}
