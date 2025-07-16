package derppool

import (
	"encoding/hex"
	"errors"
	"fmt"
	"sync"

	"go4.org/mem"
	wgdevice "golang.zx2c4.com/wireguard/device"
	tsderp "tailscale.com/derp"
	"tailscale.com/derp/derphttp"
	"tailscale.com/net/netmon"
	"tailscale.com/types/key"
)

type DerpPool interface {
	GetAddresses() []string
	AddDerpClient(privateKey wgdevice.NoisePrivateKey, addr string) error

	Send(bufs [][]byte, publicKey wgdevice.NoisePublicKey) error
	ReceiveChannel() <-chan ReceivedPacket

	Clear()
	Close()
}

type derpPool struct {
	log  *wgdevice.Logger
	mu   sync.RWMutex
	wg   sync.WaitGroup
	pool map[string]*derp

	packetCh chan ReceivedPacket
}

// GetAddresses implements DerpPool.
func (d *derpPool) GetAddresses() []string {
	d.mu.Lock()
	defer d.mu.Unlock()

	var addresses []string
	for addr := range d.pool {
		addresses = append(addresses, addr)
	}
	return addresses
}

type derp struct {
	sync.RWMutex
	client *derphttp.Client
	addr   string
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

func New(logger *wgdevice.Logger) DerpPool {
	return &derpPool{
		log:      logger,
		mu:       sync.RWMutex{},
		packetCh: make(chan ReceivedPacket, 1024),
		pool:     make(map[string]*derp),
	}
}

func (d *derpPool) AddDerpClient(privateKey wgdevice.NoisePrivateKey, addr string) error {
	hexPrivateKey := hex.EncodeToString(privateKey[:])
	derpKey, err := key.ParseNodePrivateUntyped(mem.S(hexPrivateKey))
	if err != nil {
		return err
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	_, exists := d.pool[addr]
	if exists {
		return nil
	}

	client, err := derphttp.NewClient(derpKey, addr, d.log.Verbosef, netmon.NewStatic())
	if err != nil {
		return err
	}

	derp := &derp{
		addr:   addr,
		client: client,
	}

	d.pool[addr] = derp

	d.wg.Add(1)
	go func() {
		defer d.wg.Done()
		for {
			msg, err := derp.Recv()
			if err == derphttp.ErrClientClosed {
				d.log.Verbosef("Derp client closed %s: %v", addr, err)
				return
			}
			if err != nil {
				d.log.Errorf("Error while receiving from %s: %v", addr, err)
				continue
			}
			if msg == nil {
				d.log.Verbosef("message nil %s", derp.addr)
				continue
			}
			d.packetCh <- msg
		}
	}()
	return nil
}

func (d *derpPool) Close() {
	d.Clear()
	close(d.packetCh)
}

func (d *derpPool) Clear() {
	d.mu.Lock()
	defer d.mu.Unlock()

	for _, derp := range d.pool {
		derp.Lock()
		if derp.client != nil {
			derp.client.Close()
			derp.client = nil
		}
		derp.Unlock()
	}
	d.wg.Wait()
	d.pool = make(map[string]*derp)
}

func (d *derpPool) Send(bufs [][]byte, publicKey wgdevice.NoisePublicKey) error {
	d.mu.RLock()
	defer d.mu.RUnlock()

	var errs error
	for _, derp := range d.pool {
		err := derp.Send(bufs, publicKey)
		if err == nil {
			return nil
		}
		errs = errors.Join(errs, err)
	}
	return nil
}

func (d *derpPool) ReceiveChannel() <-chan ReceivedPacket {
	return d.packetCh
}

func (d *derp) Send(bufs [][]byte, publicKey wgdevice.NoisePublicKey) error {
	// Convert wgdevice.NoisePublicKey to the key type expected by DERP client
	derpKey := key.NodePublicFromRaw32(mem.B(publicKey[:]))

	d.RLock()
	defer d.RUnlock()
	for _, buf := range bufs {
		if err := d.client.Send(derpKey, buf); err != nil {
			return err
		}
	}
	return nil
}

func (d *derp) Recv() (ReceivedPacket, error) {
	d.RLock()
	defer d.RUnlock()
	msg, err := d.client.Recv()
	if err != nil {
		return nil, err
	}
	return newReceivedPacket(msg)
}

func newReceivedPacket(msg tsderp.ReceivedMessage) (ReceivedPacket, error) {
	packet, ok := msg.(tsderp.ReceivedPacket)
	if !ok {
		return nil, nil // Skip invalid message types
	}
	if len(packet.Data) == 0 {
		return nil, fmt.Errorf("empty data in derp packet")
	}

	p := &receivedPacket{data: packet.Data}
	copy(p.source[:], packet.Source.AppendTo([]byte{})[:])
	return p, nil
}
