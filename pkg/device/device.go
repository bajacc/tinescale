package device

import (
	"io"
	"net"
	"sync"
	"time"

	"github.com/bajacc/tinescale/pkg/derppool"
	"github.com/bajacc/tinescale/pkg/endpointpool"
	"github.com/bajacc/tinescale/pkg/stunPool"
	"github.com/bajacc/tinescale/pkg/tun"
	"golang.zx2c4.com/wireguard/conn"
	wgdevice "golang.zx2c4.com/wireguard/device"
	wgtun "golang.zx2c4.com/wireguard/tun"
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

	tun *tun.InterceptTun

	net struct {
		sync.RWMutex
		bind *Bind
	}
	stunPool     stunPool.StunPool
	derpPool     derppool.DerpPool
	endpointPool endpointpool.EndpointPool

	// the following fields are mirrors from wg device

	staticIdentity struct {
		sync.RWMutex
		privateKey wgdevice.NoisePrivateKey
		publicKey  wgdevice.NoisePublicKey
	}
}

func (d *Device) AddPeer(key wgdevice.NoisePublicKey) {
	d.tun.AddPeer(key)
	d.endpointPool.AddPeer(key)
}

func (d *Device) RemovePeer(key wgdevice.NoisePublicKey) {
	d.endpointPool.RemovePeer(key)
	d.tun.RemovePeer(key)
}

func (d *Device) ClearPeers() {
	d.endpointPool.ClearPeers()
	d.tun.ClearPeers()
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

func NewDevice(t wgtun.Device, bind conn.Bind, logger *wgdevice.Logger) DeviceInterface {
	var device Device
	device.log = logger
	device.tun = tun.New(logger, t)
	device.derpPool = derppool.New(logger)
	device.stunPool = stunPool.New(30*time.Second, 5*time.Second, logger)
	device.net.bind = NewBind(bind, &device, logger)
	device.endpointPool = endpointpool.New(logger, device.tun, bind, device.stunPool, 5*time.Second)
	device.inner = wgdevice.NewDevice(device.tun, device.net.bind, logger)

	return &device
}
