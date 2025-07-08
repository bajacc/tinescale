package device

import (
	"fmt"
	"net/netip"
	"strings"

	"golang.zx2c4.com/wireguard/conn"
)

type Bind struct {
	inner  conn.Bind
	device *Device
}

type Endpoint struct {
	proto string
	inner conn.Endpoint
}

// ClearSrc implements conn.Endpoint.
func (e *Endpoint) ClearSrc() {
	e.inner.ClearSrc()
}

// DstIP implements conn.Endpoint.
func (e *Endpoint) DstIP() netip.Addr {
	return e.inner.DstIP()
}

// DstToBytes implements conn.Endpoint.
func (e *Endpoint) DstToBytes() []byte {
	return e.inner.DstToBytes()
}

// DstToString implements conn.Endpoint.
func (e *Endpoint) DstToString() string {
	return e.inner.DstToString()
}

// SrcIP implements conn.Endpoint.
func (e *Endpoint) SrcIP() netip.Addr {
	return e.inner.SrcIP()
}

// SrcToString implements conn.Endpoint.
func (e *Endpoint) SrcToString() string {
	return e.inner.SrcToString()
}

func (b *Bind) ParseEndpoint(s string) (conn.Endpoint, error) {
	proto, value, ok := strings.Cut(s, "://")
	if !ok {
		inner, err := b.inner.ParseEndpoint(s)
		if err != nil {
			return nil, err
		}
		return &Endpoint{
			inner: inner,
			proto: "udp",
		}, nil
	}
	inner, err := b.inner.ParseEndpoint(value)
	if err != nil {
		return nil, err
	}
	switch proto {
	case "derp":
		return &Endpoint{
			inner: inner,
			proto: "derp",
		}, nil
	default:
		return nil, fmt.Errorf("Error parsing %s: proto %s not known", s, proto)
	}
}

func (b *Bind) BatchSize() int {
	return b.inner.BatchSize()
}

func (b *Bind) Close() error {
	return b.inner.Close()
}

func (b *Bind) SetMark(mark uint32) error {
	b.inner.SetMark(mark)
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
	switch ep.proto {
	case "udp":
		return b.inner.Send(bufs, ep.inner)
	case "derp":
		return b.device.sendViaDERP(bufs, ep.inner)
	default:
		return fmt.Errorf("unknown protocol: %s", ep.proto)
	}
}
