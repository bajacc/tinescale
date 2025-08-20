package device

import (
	"context"
	"fmt"
	"net"

	"github.com/bajacc/tinescale/pkg/endpointpool"
	"golang.zx2c4.com/wireguard/conn"
	wgdevice "golang.zx2c4.com/wireguard/device"
)

type Bind struct {
	log          *wgdevice.Logger
	inner        conn.Bind
	endpointPool endpointpool.EndpointPool
	cancel       context.CancelFunc
}

func NewBind(inner conn.Bind, endpointPool endpointpool.EndpointPool, logger *wgdevice.Logger) *Bind {
	return &Bind{
		inner:        inner,
		endpointPool: endpointPool,
		log:          logger,
		cancel:       func() {},
	}
}

func (b *Bind) ParseEndpoint(s string) (conn.Endpoint, error) {
	var publicKey wgdevice.NoisePublicKey
	err := publicKey.FromHex(s)
	if err != nil {
		return nil, err
	}
	return endpointpool.NewEndpoint(publicKey), nil
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
	for _, recv := range innerFns {
		fn := b.endpointPool.GetRecv(recv)
		fns = append(fns, fn)
	}

	epPoolFn := func(bufs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		select {
		case <-ctx.Done():
			return 0, net.ErrClosed
		case packet, ok := <-b.endpointPool.ReceiveChannel():
			if !ok {
				return 0, fmt.Errorf("derp pool channel closed")
			}
			n := copy(bufs[0][:], packet.Data())
			sizes[0] = n
			eps[0] = endpointpool.NewEndpoint(packet.Source())
			return 1, nil
		}
	}

	fns = append(fns, epPoolFn)

	return fns, actualPort, err
}

func (b *Bind) Send(bufs [][]byte, endpoint conn.Endpoint) error {
	return b.endpointPool.SendBest(bufs, endpoint)
}
