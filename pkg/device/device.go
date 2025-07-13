package device

import (
	"io"
	"net"
	"sync"

	"go4.org/mem"
	"golang.zx2c4.com/wireguard/conn"
	wgdevice "golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"tailscale.com/derp"
	"tailscale.com/derp/derphttp"
	"tailscale.com/types/key"
	tskey "tailscale.com/types/key"
)

type DeviceInterface interface {
	IpcGetOperation(w io.Writer) error
	IpcSetOperation(r io.Reader) error
	IpcHandle(socket net.Conn)
	Wait() chan struct{}
	Close()
}

type Device struct {
	inner *wgdevice.Device

	log      *wgdevice.Logger
	ipcMutex sync.RWMutex

	net struct {
		sync.RWMutex
		bind *Bind
	}
	stun struct {
		sync.RWMutex
		clients []*Stun
	}
	derp struct {
		sync.RWMutex
		clients []*Derp
	}

	// the following fields are mirrors from wg device

	staticIdentity struct {
		sync.RWMutex
		privateKeyHex string
		privateKey    wgdevice.NoisePrivateKey
		publicKey     wgdevice.NoisePublicKey
	}

	peers struct {
		sync.RWMutex // protects keyMap
		keyMap       map[wgdevice.NoisePublicKey]*Peer
	}

	listenPort struct {
		sync.RWMutex
		val uint16
	}
}

type Peer struct {
	endpoint struct {
		sync.RWMutex
		uapi conn.Endpoint   // uapi configured endpoint
		stun []conn.Endpoint // stun configured endpoints
	}
}

type Stun struct {
	sync.RWMutex
	conn net.Conn
	addr string
}

type Derp struct {
	sync.RWMutex
	val  *derphttp.Client
	addr string
}

func (d *Derp) New(addr string) *Derp {
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

	derpKey, err := tskey.ParseNodePrivateUntyped(mem.S(privateKeyHex))
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

func (d *Derp) Recv(bufs [][]byte, sizes []int, device *Device) (int, error) {
	if err := d.init(device); err != nil {
		return 0, err
	}
	d.RLock()
	defer d.RUnlock()

	count := 0
	for i := range bufs {
		msg, err := d.val.Recv()
		if err != nil {
			return count, err
		}
		packet, ok := msg.(*derp.ReceivedPacket)
		if !ok {
			continue // Skip invalid message types
		}

		// Check if buffer is large enough
		if len(bufs[i]) < len(packet.Data) {
			// Buffer too small, skip this packet
			device.log.Verbosef("DERP: dropping packet of size %d (buffer size %d)", len(packet.Data), len(bufs[i]))
			continue
		}

		// Copy packet data to buffer
		n := copy(bufs[i], packet.Data)
		sizes[i] = n
		count++

		// If we don't have more space, break
		if i >= len(bufs)-1 {
			break
		}
	}
	return count, nil
}

func (device *Device) Wait() chan struct{} {
	return device.inner.Wait()
}

func (device *Device) Close() {
	device.ipcMutex.Lock()
	defer device.ipcMutex.Unlock()
	device.inner.Close()
}

type TunDevice struct {
	tun.Device
}

func (t *TunDevice) Read(bufs [][]byte, sizes []int, offset int) (n int, err error) {
	return t.Device.Read(bufs, sizes, offset)
}

func NewDevice(tunDevice tun.Device, bind conn.Bind, logger *wgdevice.Logger) DeviceInterface {
	tun := &TunDevice{
		tunDevice,
	}
	device := new(Device)
	device.log = logger
	device.net.bind = NewBind(bind, device, logger)
	device.inner = wgdevice.NewDevice(tun, device.net.bind, logger)
	return device
}
