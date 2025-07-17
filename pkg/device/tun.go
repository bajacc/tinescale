package device

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"os"
	"sync"
	"time"

	wgdevice "golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

type WireGuardDialer struct {
	localKey wgdevice.NoisePublicKey
	localNet net.IPNet
	localIp  net.IP
	conns    map[wgdevice.NoisePublicKey]net.Conn
}

func NewWireGuardDialer(localKey wgdevice.NoisePublicKey, localNet net.IPNet) (*WireGuardDialer, error) {
	localIp, err := PublicKeyToIP(localNet, localKey)
	if err != nil {
		return nil, err
	}

	return &WireGuardDialer{
		localKey: localKey,
		localNet: localNet,
		localIp:  localIp,
		conns:    make(map[wgdevice.NoisePublicKey]net.Conn),
	}, nil
}

func (wd *WireGuardDialer) Dial(ctx context.Context, address string) (net.Conn, error) {
	peerKeyBytes, err := hex.DecodeString(address)
	if err != nil {
		return nil, err
	}

	peerKey := wgdevice.NoisePublicKey(peerKeyBytes)

	conn, exists := wd.conns[peerKey]
	if exists {
		return conn, nil
	}

	peerIp, err := PublicKeyToIP(wd.localNet, peerKey)
	if err != nil {
		return nil, err
	}

	conn = &WireGuardConn{
		localIp:   wd.localIp,
		peerIp:    peerIp,
		readChan:  make(chan []byte, 100),
		writeChan: make(chan []byte, 100),
	}

	return conn, nil
}

type WireGuardConn struct {
	tunDevice interface{}
	localIp   net.IP
	peerIp    net.IP
	readChan  chan []byte
	writeChan chan []byte
}

// Close implements net.Conn.
func (w *WireGuardConn) Close() error {
	panic("unimplemented")
}

// LocalAddr implements net.Conn.
func (w *WireGuardConn) LocalAddr() net.Addr {
	panic("unimplemented")
}

// Read implements net.Conn.
func (w *WireGuardConn) Read(b []byte) (n int, err error) {
	panic("unimplemented")
}

// RemoteAddr implements net.Conn.
func (w *WireGuardConn) RemoteAddr() net.Addr {
	panic("unimplemented")
}

// SetDeadline implements net.Conn.
func (w *WireGuardConn) SetDeadline(t time.Time) error {
	panic("unimplemented")
}

// SetReadDeadline implements net.Conn.
func (w *WireGuardConn) SetReadDeadline(t time.Time) error {
	panic("unimplemented")
}

// SetWriteDeadline implements net.Conn.
func (w *WireGuardConn) SetWriteDeadline(t time.Time) error {
	panic("unimplemented")
}

// Write implements net.Conn.
func (w *WireGuardConn) Write(b []byte) (n int, err error) {
	panic("unimplemented")
}

type interceptTun struct {
	inner tun.Device
	conns sync.Map // map[string]*tunConn
}

// BatchSize implements tun.Device.
func (t *interceptTun) BatchSize() int {
	return t.inner.BatchSize()
}

// Close implements tun.Device.
func (t *interceptTun) Close() error {
	return t.inner.Close()
}

// Events implements tun.Device.
func (t *interceptTun) Events() <-chan tun.Event {
	return t.inner.Events()
}

// File implements tun.Device.
func (t *interceptTun) File() *os.File {
	return t.inner.File()
}

// MTU implements tun.Device.
func (t *interceptTun) MTU() (int, error) {
	return t.inner.MTU()
}

// Name implements tun.Device.
func (t *interceptTun) Name() (string, error) {
	return t.inner.Name()
}

// Read implements tun.Device.
func (t *interceptTun) Read(bufs [][]byte, sizes []int, offset int) (n int, err error) {
	return t.inner.Read(bufs, sizes, offset)
}

// Write implements tun.Device.
func (t *interceptTun) Write(bufs [][]byte, offset int) (int, error) {
	return t.inner.Write(bufs, offset)
}

func NewTunDevice(tun tun.Device) tun.Device {
	return &interceptTun{inner: tun}
}

// PublicKeyToIP converts a public key to an IP address
func PublicKeyToIP(ipnet net.IPNet, key wgdevice.NoisePublicKey) (net.IP, error) {
	// Hash the public key
	hash := sha256.Sum256(key[:])

	// Get prefix length
	prefixLen, _ := ipnet.Mask.Size()
	prefixBytes := prefixLen / 8
	remainingBits := prefixLen % 8

	// Create IP address
	ipLen := len(ipnet.IP)
	ip := make(net.IP, ipLen)

	// Copy full prefix bytes
	copy(ip[:prefixBytes], ipnet.IP[:prefixBytes])
	mask := byte(0xFF << remainingBits)
	ip[prefixBytes] = (ipnet.IP[prefixBytes] & ^mask) | (hash[prefixBytes] & mask)
	// Copy the hash remain
	copy(ip[prefixBytes+1:], hash[prefixBytes+1:])

	return ip, nil
}
