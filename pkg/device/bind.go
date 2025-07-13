package device

import (
	"fmt"
	"net/netip"

	"go4.org/mem"
	"golang.zx2c4.com/wireguard/conn"
	wgdevice "golang.zx2c4.com/wireguard/device"
	"tailscale.com/types/key"
)

type Bind struct {
	inner  conn.Bind
	device *Device
}

type Endpoint struct {
	origPubKey wgdevice.NoisePublicKey
}

func NewBind(inner conn.Bind, device *Device) *Bind {
	return &Bind{
		inner:  inner,
		device: device,
	}
}

// ClearSrc implements conn.Endpoint.
func (e *Endpoint) ClearSrc() {}

// DstIP implements conn.Endpoint.
func (e *Endpoint) DstIP() netip.Addr {
	return netip.Addr{}
}

// DstToBytes implements conn.Endpoint.
func (e *Endpoint) DstToBytes() []byte {
	return []byte{}
}

// DstToString implements conn.Endpoint.
func (e *Endpoint) DstToString() string {
	return ""
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
	return b.inner.Close()
}

func (b *Bind) SetMark(mark uint32) error {
	return b.inner.SetMark(mark)
}

func (b *Bind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	innerFns, actualPort, err := b.inner.Open(port)
	if err != nil {
		return innerFns, actualPort, err
	}

	var fns []conn.ReceiveFunc
	for _, fn := range innerFns {
		fns = append(fns, fn)
	}
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
	err = b.inner.Send(bufs, peer.endpoint.uapi)
	if err == nil {
		return nil
	}

	// else send via stun configured endpoints
	for _, stunEndpoint := range peer.endpoint.stun {
		err = b.inner.Send(bufs, stunEndpoint)
		if err == nil {
			return nil
		}
	}

	// else send via DERP
	b.device.derp.RLock()
	defer b.device.derp.RUnlock()
	for _, derpClient := range b.device.derp.clients {
		err = derpClient.Send(bufs, ep.origPubKey)
		if err == nil {
			return nil
		}
	}

	return err
}

func (d *Derp) Send(bufs [][]byte, publicKey wgdevice.NoisePublicKey) error {
	// Convert wgdevice.NoisePublicKey to the key type expected by DERP client
	d.RLock()
	defer d.RUnlock()
	derpKey := key.NodePublicFromRaw32(mem.B(publicKey[:]))

	for _, buf := range bufs {
		if err := d.val.Send(derpKey, buf); err != nil {
			return err
		}
	}
	return nil
}
