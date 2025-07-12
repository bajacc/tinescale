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
	b.device.peers.Lock()
	defer b.device.peers.Unlock()
	peer, ok := b.device.peers.keyMap[ep.origPubKey]
	if !ok {
		return fmt.Errorf("peer with public key %s not found", ep.origPubKey)
	}

	peer.endpoint.Lock()
	defer peer.endpoint.Unlock()

	return nil
}

func (d *Device) sendViaDERP(bufs [][]byte, publicKey wgdevice.NoisePublicKey) error {
	// Convert wgdevice.NoisePublicKey to the key type expected by DERP client
	derpKey := key.NodePublicFromRaw32(mem.B(publicKey[:]))

	for _, buf := range bufs {
		if err := d.derpClient.Send(derpKey, buf); err != nil {
			return err
		}
	}
	return nil
}
