package device

import (
	"io"
	"net"
	"sync"

	"golang.zx2c4.com/wireguard/conn"
	wgdevice "golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"tailscale.com/derp/derphttp"
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
		privateKey wgdevice.NoisePrivateKey
		publicKey  wgdevice.NoisePublicKey
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
	device.inner = wgdevice.NewDevice(tun, bind, logger)
	device.net.bind = NewBind(bind, device)
	device.log = logger
	return device
}
