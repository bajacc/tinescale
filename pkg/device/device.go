package device

import (
	"io"
	"net"
	"sync"

	"github.com/bajacc/tinescale/pkg/derppool"
	"github.com/bajacc/tinescale/pkg/stunPool"
	"golang.zx2c4.com/wireguard/conn"
	wgdevice "golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
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

	tun *interceptTun

	net struct {
		sync.RWMutex
		bind *Bind
	}
	stunPool stunPool.StunPool
	derpPool derppool.DerpPool

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

func (device *Device) Wait() chan struct{} {
	return device.inner.Wait()
}

func (device *Device) Close() {
	device.ipcMutex.Lock()
	defer device.ipcMutex.Unlock()
	device.inner.Close()
	device.derpPool.Close()
}

func NewDevice(tun tun.Device, bind conn.Bind, logger *wgdevice.Logger) DeviceInterface {
	var device Device
	device.tun = NewTunDevice(logger, tun)
	device.log = logger
	device.derpPool = derppool.New(logger)
	device.net.bind = NewBind(bind, &device, logger)
	device.inner = wgdevice.NewDevice(device.tun, device.net.bind, logger)

	return &device
}
