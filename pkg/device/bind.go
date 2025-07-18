package device

import (
	"context"
	"fmt"
	"net"
	"net/netip"

	"golang.zx2c4.com/wireguard/conn"
	wgdevice "golang.zx2c4.com/wireguard/device"
)

type Bind struct {
	inner  conn.Bind
	device *Device
	log    *wgdevice.Logger
	cancel context.CancelFunc
}

type Endpoint struct {
	origPubKey wgdevice.NoisePublicKey
}

func NewBind(inner conn.Bind, device *Device, logger *wgdevice.Logger) *Bind {
	return &Bind{
		inner:  inner,
		device: device,
		log:    logger,
		cancel: func() {},
	}
}

func (b *Bind) udpToTinescaleEndpoint(udpEp conn.Endpoint) *Endpoint {
	// Look through all peers to find one with matching UDP endpoint
	b.device.peers.RLock()
	defer b.device.peers.RUnlock()

	for pubKey, peer := range b.device.peers.keyMap {
		ep := func() *Endpoint {
			peer.endpoint.RLock()
			defer peer.endpoint.RUnlock()
			if peer.endpoint.uapi != nil && peer.endpoint.uapi.DstToString() == udpEp.DstToString() {
				return &Endpoint{origPubKey: pubKey}
			}

			for _, stunEndpoint := range peer.endpoint.stun {
				if stunEndpoint.DstToString() == udpEp.DstToString() {
					return &Endpoint{origPubKey: pubKey}
				}
			}
			return nil
		}()
		if ep != nil {
			return ep
		}
	}
	return nil
}

// ClearSrc implements conn.Endpoint.
func (e *Endpoint) ClearSrc() {}

// DstIP implements conn.Endpoint.
func (e *Endpoint) DstIP() netip.Addr {
	// TODO do we need that?
	// Generate a deterministic IP from the public key for rate limiting
	// Use the first 4 bytes of the public key as an IPv4 address in the 10.0.0.0/8 range
	if len(e.origPubKey) >= 4 {
		return netip.AddrFrom4([4]byte{10, e.origPubKey[0], e.origPubKey[1], e.origPubKey[2]})
	}
	return netip.Addr{}
}

// DstToBytes implements conn.Endpoint.
func (e *Endpoint) DstToBytes() []byte {
	return e.origPubKey[:]
}

// DstToString implements conn.Endpoint.
func (e *Endpoint) DstToString() string {
	return fmt.Sprintf("tinescale:%x", e.origPubKey[:8])
}

// SrcIP implements conn.Endpoint.
func (e *Endpoint) SrcIP() netip.Addr {
	return netip.Addr{}
}

// SrcToString implements conn.Endpoint.
func (e *Endpoint) SrcToString() string {
	return ""
}

func (b *Bind) ParseEndpoint(s string) (conn.Endpoint, error) {
	var publicKey wgdevice.NoisePublicKey
	err := publicKey.FromHex(s)
	if err != nil {
		return nil, err
	}
	return &Endpoint{
		origPubKey: publicKey,
	}, nil
}

func (b *Bind) ParseInnerEndpoint(s string) (conn.Endpoint, error) {
	return b.inner.ParseEndpoint(s)
}

func (b *Bind) BatchSize() int {
	return b.inner.BatchSize()
}

func (b *Bind) Close() error {
	b.cancel()
	return b.inner.Close()
}

func (b *Bind) SetMark(mark uint32) error {
	return b.inner.SetMark(mark)
}

func (b *Bind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	ctx, cancel := context.WithCancel(context.Background())
	b.cancel = cancel

	innerFns, actualPort, err := b.inner.Open(port)
	if err != nil {
		return innerFns, actualPort, err
	}

	var fns []conn.ReceiveFunc
	for _, innerFn := range innerFns {
		recv := innerFn
		fn := func(bufs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
			n, err := recv(bufs, sizes, eps)
			if err != nil {
				return n, err
			}

			for i := range n {
				tinescaleEp := b.udpToTinescaleEndpoint(eps[i])
				if tinescaleEp == nil {
					return n, fmt.Errorf("no tinescale endpoint found for %s", eps[i].DstToString())
				}
				eps[i] = tinescaleEp
			}
			return n, nil
		}
		fns = append(fns, fn)
	}

	derpFn := func(bufs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		select {
		case <-ctx.Done():
			return 0, net.ErrClosed
		case packet, ok := <-b.device.derpPool.ReceiveChannel():
			if !ok {
				return 0, fmt.Errorf("derp pool channel closed")
			}
			n := copy(bufs[0][:], packet.Data())
			sizes[0] = n
			eps[0] = &Endpoint{
				origPubKey: packet.Source(),
			}
			return 1, nil
		}
	}
	fns = append(fns, derpFn)

	return fns, actualPort, err
}

func (b *Bind) Send(bufs [][]byte, endpoint conn.Endpoint) error {
	ep, ok := endpoint.(*Endpoint)
	if !ok {
		return fmt.Errorf("Error Enpoint is not a tinescale endpoint")
	}
	b.device.peers.RLock()
	defer b.device.peers.RUnlock()
	peer, ok := b.device.peers.keyMap[ep.origPubKey]
	if !ok {
		return fmt.Errorf("peer with public key %s not found", ep.origPubKey)
	}

	peer.endpoint.RLock()
	defer peer.endpoint.RUnlock()

	var err error

	// send via uapi configured endpoints
	if peer.endpoint.uapi != nil {
		err = b.inner.Send(bufs, peer.endpoint.uapi)
		if err == nil {
			return nil
		}
	}

	// else send via stun configured endpoints
	for _, stunEndpoint := range peer.endpoint.stun {
		err = b.inner.Send(bufs, stunEndpoint)
		if err == nil {
			return nil
		}
	}

	// else send via DERP
	b.device.derpPool.Send(bufs, ep.origPubKey)

	return err
}
