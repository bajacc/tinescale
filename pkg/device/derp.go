package device

import (
	"sync"

	"go4.org/mem"
	wgdevice "golang.zx2c4.com/wireguard/device"
	"tailscale.com/derp"
	"tailscale.com/derp/derphttp"
	"tailscale.com/types/key"
)

type Derp struct {
	sync.RWMutex
	val  *derphttp.Client
	addr string
}

func NewDerp(addr string) *Derp {
	return &Derp{
		addr: addr,
	}
}

func (d *Derp) init(device *Device) error {
	d.RLock()
	client := d.val
	d.RUnlock()
	if client != nil {
		return nil
	}
	device.staticIdentity.RLock()
	privateKeyHex := device.staticIdentity.privateKeyHex
	device.staticIdentity.RUnlock()

	derpKey, err := key.ParseNodePrivateUntyped(mem.S(privateKeyHex))
	if err != nil {
		return err
	}

	d.Lock()
	defer d.Unlock()
	d.val, err = derphttp.NewClient(derpKey, d.addr, device.log.Verbosef, nil)
	return err
}

func (d *Derp) Send(bufs [][]byte, publicKey wgdevice.NoisePublicKey, device *Device) error {
	// Convert wgdevice.NoisePublicKey to the key type expected by DERP client
	if err := d.init(device); err != nil {
		return err
	}
	derpKey := key.NodePublicFromRaw32(mem.B(publicKey[:]))

	d.RLock()
	defer d.RUnlock()
	for _, buf := range bufs {
		if err := d.val.Send(derpKey, buf); err != nil {
			return err
		}
	}
	return nil
}

func (d *Derp) Recv(bufs [][]byte, sizes []int, publicKeys []wgdevice.NoisePublicKey, device *Device) (int, error) {
	if err := d.init(device); err != nil {
		return 0, err
	}
	d.RLock()
	defer d.RUnlock()

	// Only receive one message to avoid blocking
	msg, err := d.val.Recv()
	if err != nil {
		return 0, err
	}

	packet, ok := msg.(*derp.ReceivedPacket)
	if !ok {
		return 0, nil // Skip invalid message types
	}

	// Check if buffer is large enough
	if len(bufs[0]) < len(packet.Data) {
		// Buffer too small, skip this packet
		device.log.Verbosef("DERP: dropping packet of size %d (buffer size %d)", len(packet.Data), len(bufs[0]))
		return 0, nil
	}

	// Copy packet data to buffer
	n := copy(bufs[0], packet.Data)
	sizes[0] = n

	// Convert sender's key to NoisePublicKey
	copy(publicKeys[0][:], packet.Source.AppendTo([]byte{})[:])

	return 1, nil
}
