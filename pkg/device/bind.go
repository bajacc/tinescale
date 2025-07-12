package device

import (
	"fmt"
	"net/netip"

	"golang.zx2c4.com/wireguard/conn"
	wgdevice "golang.zx2c4.com/wireguard/device"
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
	_, ok := endpoint.(*Endpoint)
	if !ok {
		return fmt.Errorf("Error Enpoint is not a tinescale endpoint")
	}
	return nil
}
