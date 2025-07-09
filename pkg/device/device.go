package device

import (
	"io"
	"net"
	"sync"

	"golang.zx2c4.com/wireguard/conn"
	wgdevice "golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"tailscale.com/derp"
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
		bind conn.Bind
	}
	stunServers struct {
		sync.RWMutex
		endpoints []conn.Endpoint
	}
	derpServers struct {
		sync.RWMutex
		endpoints []conn.Endpoint
	}

	derpClient *derp.Client

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
}

func (d *Device) sendViaDERP(bufs [][]byte, endpoint conn.Endpoint) error {
	return nil
}

type Peer struct {
	endpoint struct {
		sync.Mutex
		val conn.Endpoint
	}
}

func (device *Device) Wait() chan struct{} {
	return device.inner.Wait()
}

func (device *Device) Close() {
	device.ipcMutex.Lock()
	defer device.ipcMutex.Unlock()
	device.inner.Close()
}

func (d *Device) removeStunServer(toRemove conn.Endpoint) {
	d.stunServers.Lock()
	defer d.stunServers.Unlock()

	result := d.stunServers.endpoints[:0] // reuse underlying array
	for _, ep := range d.stunServers.endpoints {
		if ep.DstToString() != toRemove.DstToString() {
			result = append(result, ep)
		}
	}
	d.stunServers.endpoints = result
}

func (d *Device) removeDerpServer(toRemove conn.Endpoint) {
	d.derpServers.Lock()
	defer d.derpServers.Unlock()

	result := d.derpServers.endpoints[:0] // reuse underlying array
	for _, ep := range d.derpServers.endpoints {
		if ep.DstToString() != toRemove.DstToString() {
			result = append(result, ep)
		}
	}
	d.derpServers.endpoints = result
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
	device.log = logger
	device.net.bind = bind

	return device
}
