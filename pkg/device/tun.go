package device

import (
	"crypto/sha256"
	"net"
	"os"

	wgdevice "golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

type interceptTun struct {
	inner tun.Device
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
