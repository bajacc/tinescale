package device

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	wgdevice "golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

type WireGuardAddr struct {
	Key wgdevice.NoisePublicKey
}

func (w WireGuardAddr) Network() string {
	return "wireguard"
}

func (w WireGuardAddr) String() string {
	return hex.EncodeToString(w.Key[:])
}

type WireGuardConn struct {
	localIp  netip.Addr
	remoteIp netip.Addr

	localAddr  *WireGuardAddr
	remoteAddr *WireGuardAddr

	inboundCh  chan []byte
	outboundCh chan []byte
	done       chan struct{}

	readDeadline  atomic.Value
	writeDeadline atomic.Value
}

// Close implements net.Conn.
func (w *WireGuardConn) Close() error {
	close(w.done)
	close(w.inboundCh)
	return nil
}

// LocalAddr implements net.Conn.
func (w *WireGuardConn) LocalAddr() net.Addr {
	return w.localAddr
}

// RemoteAddr implements net.Conn.
func (w *WireGuardConn) RemoteAddr() net.Addr {
	return w.remoteAddr
}

// SetDeadline implements net.Conn.
func (w *WireGuardConn) SetDeadline(t time.Time) error {
	w.readDeadline.Store(t)
	w.writeDeadline.Store(t)
	return nil
}

// SetReadDeadline implements net.Conn.
func (w *WireGuardConn) SetReadDeadline(t time.Time) error {
	w.readDeadline.Store(t)
	return nil
}

func (w *WireGuardConn) getReadDeadline() time.Time {
	if v := w.readDeadline.Load(); v != nil {
		return v.(time.Time)
	}
	return time.Time{}
}

// SetWriteDeadline implements net.Conn.
func (w *WireGuardConn) SetWriteDeadline(t time.Time) error {
	w.writeDeadline.Store(t)
	return nil
}

func (w *WireGuardConn) getWriteDeadline() time.Time {
	if v := w.writeDeadline.Load(); v != nil {
		return v.(time.Time)
	}
	return time.Time{}
}

// Write implements net.Conn.
func (w *WireGuardConn) Write(b []byte) (n int, err error) {
	var timeoutCh <-chan time.Time

	if deadline := w.getWriteDeadline(); !deadline.IsZero() {
		timeoutCh = time.After(time.Until(deadline))
	}

	select {
	case w.outboundCh <- b:
		return len(b), nil
	case <-w.done:
		return 0, net.ErrClosed
	case <-timeoutCh:
		return 0, os.ErrDeadlineExceeded
	}
}

// Read implements net.Conn.
func (w *WireGuardConn) Read(b []byte) (n int, err error) {
	var timeoutCh <-chan time.Time

	if deadline := w.getReadDeadline(); !deadline.IsZero() {
		timeoutCh = time.After(time.Until(deadline))
	}

	select {
	case pkt := <-w.inboundCh:
		return copy(b, pkt), nil
	case <-w.done:
		return 0, net.ErrClosed
	case <-timeoutCh:
		return 0, os.ErrDeadlineExceeded
	}
}

type interceptTun struct {
	inner tun.Device
	log   *wgdevice.Logger

	localKey wgdevice.NoisePublicKey
	localNet netip.Prefix
	localIp  netip.Addr
	mu       sync.RWMutex
	conns    map[netip.Addr]*WireGuardConn

	outboundCh  chan []byte
	readErrorCh chan error
	done        chan struct{}
}

// BatchSize implements tun.Device.
func (t *interceptTun) BatchSize() int {
	return t.inner.BatchSize()
}

// Close implements tun.Device.
func (t *interceptTun) Close() error {
	close(t.done)
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, conn := range t.conns {
		conn.Close()
	}
	close(t.outboundCh)
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

func (t *interceptTun) Lookup(ipBytes []byte) *WireGuardConn {
	ip, ok := netip.AddrFromSlice(ipBytes)
	if !ok {
		return nil
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	conn, ok := t.conns[ip]
	if !ok {
		return nil
	}
	return conn
}

// Read implements tun.Device.
func (t *interceptTun) Read(bufs [][]byte, sizes []int, offset int) (n int, err error) {
	select {
	case <-t.done:
		return 0, net.ErrClosed
	case err := <-t.readErrorCh:
		if err != nil {
			return 0, err
		}
	case pkt := <-t.outboundCh:
		size := copy(bufs[0][:], pkt[:])
		sizes[0] = size
		// TODO offset
		return 1, nil
	}
	return 0, nil
}

// Write implements tun.Device.
func (t *interceptTun) Write(bufs [][]byte, offset int) (int, error) {
	var newBufs [][]byte
	connWrite := 0
	for i := 0; i < len(bufs); i++ {
		packet := bufs[i][offset:]
		if len(packet) == 0 {
			continue
		}

		var conn *WireGuardConn
		switch packet[0] >> 4 {
		case 4:
			if len(packet) < ipv4.HeaderLen {
				continue
			}
			dst := packet[wgdevice.IPv4offsetDst : wgdevice.IPv4offsetDst+net.IPv4len]
			conn = t.Lookup(dst)
		case 6:
			if len(packet) < ipv6.HeaderLen {
				continue
			}
			dst := packet[wgdevice.IPv6offsetDst : wgdevice.IPv6offsetDst+net.IPv6len]
			conn = t.Lookup(dst)
		default:
			t.log.Verbosef("try to write packet with unknown IP version")
		}

		if conn != nil {
			conn.inboundCh <- packet
			connWrite += 1
		} else {
			newBufs = append(newBufs, bufs[i])
		}
	}
	tunWrite, err := t.inner.Write(newBufs, offset)
	if err != nil {
		return 0, err
	}
	return tunWrite + connWrite, nil
}

func (t *interceptTun) GetDialFunc() func(ctx context.Context, key string) (net.Conn, error) {
	return func(ctx context.Context, key string) (net.Conn, error) {
		remoteKeyBytes, err := hex.DecodeString(key)
		if err != nil {
			return nil, err
		}

		remoteKey := wgdevice.NoisePublicKey(remoteKeyBytes)

		remoteIp, ok := PublicKeyToIP(t.localNet, remoteKey)
		if !ok {
			return nil, fmt.Errorf("cannot convert %s to ip", remoteKey)
		}

		conn, exists := t.conns[remoteIp]
		if exists {
			return conn, nil
		}

		conn = &WireGuardConn{
			localIp:    t.localIp,
			remoteIp:   remoteIp,
			localAddr:  &WireGuardAddr{t.localKey},
			remoteAddr: &WireGuardAddr{remoteKey},
			inboundCh:  make(chan []byte, 1024),
			outboundCh: t.outboundCh,
		}

		return conn, nil
	}
}

func (t *interceptTun) routineReadFromTUN() {
	var (
		batchSize = t.inner.BatchSize()
		bufs      = make([][]byte, batchSize)
		sizes     = make([]int, batchSize)
	)

	for i := range bufs {
		bufs[i] = make([]byte, wgdevice.MaxMessageSize)
	}

	for {

		n, err := t.inner.Read(bufs, sizes, 0)
		if err != nil {
			t.readErrorCh <- err
			if !errors.Is(err, os.ErrClosed) {
				t.log.Errorf("Failed to read packet from TUN device: %v", err)
				continue
			}
			return
		}

		for i := range n {
			t.outboundCh <- bufs[i][0:sizes[i]]
		}
	}
}

func NewTunDevice(logger *wgdevice.Logger, tun tun.Device, localKey wgdevice.NoisePublicKey, localNet netip.Prefix) (tun.Device, error) {
	localIp, ok := PublicKeyToIP(localNet, localKey)
	if !ok {
		return nil, fmt.Errorf("cannot convert %s to ip", localKey)
	}

	t := &interceptTun{
		inner:       tun,
		log:         logger,
		localKey:    localKey,
		localIp:     localIp,
		localNet:    localNet,
		conns:       map[netip.Addr]*WireGuardConn{},
		outboundCh:  make(chan []byte, 1024),
		readErrorCh: make(chan error),
		done:        make(chan struct{}),
	}

	go t.routineReadFromTUN()

	return t, nil
}

// PublicKeyToIP converts a public key to an IP address
func PublicKeyToIP(prefix netip.Prefix, key wgdevice.NoisePublicKey) (netip.Addr, bool) {
	// Hash the public key
	hash := sha256.Sum256(key[:])

	networkAddr := prefix.Addr()
	prefixLen := prefix.Bits()
	prefixBytes := prefixLen / 8
	remainingBits := prefixLen % 8

	result := networkAddr.AsSlice()

	mask := byte(0xFF << remainingBits)
	result[prefixBytes] |= hash[prefixBytes] & ^mask
	copy(result[prefixBytes+1:], hash[prefixBytes+1:])

	return netip.AddrFromSlice(result)
}
