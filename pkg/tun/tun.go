package tun

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"

	"github.com/bajacc/tinescale/pkg/helper"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	wgdevice "golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

type InterceptTun struct {
	inner tun.Device
	log   *wgdevice.Logger

	localKey wgdevice.NoisePublicKey
	localNet netip.Prefix
	localIp  netip.Addr

	mu      sync.RWMutex
	ipToKey map[netip.Addr]wgdevice.NoisePublicKey

	readCh     chan *readResult
	outboundCh chan *PubKeyPacket
	inboundCh  chan *PubKeyPacket

	ctx    context.Context
	cancel context.CancelFunc
}

type readResult struct {
	bufs  [][]byte
	sizes []int
	n     int
	err   error
}

type PubKeyPacket struct {
	src  wgdevice.NoisePublicKey
	dst  wgdevice.NoisePublicKey
	data []byte
}

func (p *PubKeyPacket) Src() wgdevice.NoisePublicKey {
	return p.src
}

func (p *PubKeyPacket) Dst() wgdevice.NoisePublicKey {
	return p.dst
}

func (p *PubKeyPacket) Data() []byte {
	return p.data
}

func New(logger *wgdevice.Logger, tun tun.Device) *InterceptTun {
	ctx, cancel := context.WithCancel(context.Background())

	t := &InterceptTun{
		inner:      tun,
		log:        logger,
		localNet:   netip.MustParsePrefix("fd00::/8"),
		ipToKey:    make(map[netip.Addr]wgdevice.NoisePublicKey),
		readCh:     make(chan *readResult),
		outboundCh: make(chan *PubKeyPacket, 1024),
		inboundCh:  make(chan *PubKeyPacket, 1024),
		ctx:        ctx,
		cancel:     cancel,
	}

	go t.routineReadFromTUN()

	return t
}

func (t *InterceptTun) SetLocalKey(localKey wgdevice.NoisePublicKey) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	localIp, ok := helper.PublicKeyToIP(t.localNet, localKey)
	if !ok {
		return fmt.Errorf("cannot convert %s to ip", localKey)
	}

	t.localKey = localKey
	t.localIp = localIp
	return nil
}

func (t *InterceptTun) SetLocaNet(localNet netip.Prefix) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	localIp, ok := helper.PublicKeyToIP(localNet, t.localKey)
	if !ok {
		return fmt.Errorf("cannot convert %s to ip", t.localKey)
	}

	newIpToKey := make(map[netip.Addr]wgdevice.NoisePublicKey)
	for _, key := range t.ipToKey {
		ip, ok := helper.PublicKeyToIP(localNet, key)
		if !ok {
			return fmt.Errorf("cannot convert %s to ip", key)
		}
		newIpToKey[ip] = key
	}

	t.ipToKey = newIpToKey
	t.localNet = localNet
	t.localIp = localIp
	return nil
}

// BatchSize implements tun.Device.
func (t *InterceptTun) BatchSize() int {
	return t.inner.BatchSize()
}

// Close implements tun.Device.
func (t *InterceptTun) Close() error {
	t.cancel()
	close(t.inboundCh)
	close(t.outboundCh)
	return t.inner.Close()
}

// Events implements tun.Device.
func (t *InterceptTun) Events() <-chan tun.Event {
	return t.inner.Events()
}

// File implements tun.Device.
func (t *InterceptTun) File() *os.File {
	return t.inner.File()
}

// MTU implements tun.Device.
func (t *InterceptTun) MTU() (int, error) {
	return t.inner.MTU()
}

// Name implements tun.Device.
func (t *InterceptTun) Name() (string, error) {
	return t.inner.Name()
}

func (t *InterceptTun) AddPeer(key wgdevice.NoisePublicKey) error {
	ip, ok := helper.PublicKeyToIP(t.localNet, key)
	if !ok {
		return fmt.Errorf("could not create ip from public key")
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	_, exists := t.ipToKey[ip]
	if exists {
		return fmt.Errorf("peer already exists")
	}
	t.ipToKey[ip] = key
	return nil
}

func (t *InterceptTun) toIpPacket(ipPkt []byte, pkPkt *PubKeyPacket) (int, bool) {
	srcIP, ok1 := helper.PublicKeyToIP(t.localNet, pkPkt.src)
	dstIP, ok2 := helper.PublicKeyToIP(t.localNet, pkPkt.dst)
	if !ok1 || !ok2 {
		return 0, false
	}
	src := srcIP.AsSlice()
	dst := dstIP.AsSlice()
	if srcIP.Is4() {
		copy(ipPkt[wgdevice.IPv4offsetDst:wgdevice.IPv4offsetDst+net.IPv4len], dst)
		copy(ipPkt[wgdevice.IPv4offsetSrc:wgdevice.IPv4offsetSrc+net.IPv4len], src)
		copy(ipPkt[ipv4.HeaderLen:], pkPkt.data) // header length without extension headers
		return len(pkPkt.data) + ipv4.HeaderLen, true
	} else {
		copy(ipPkt[wgdevice.IPv6offsetDst:wgdevice.IPv6offsetDst+net.IPv6len], dst)
		copy(ipPkt[wgdevice.IPv6offsetSrc:wgdevice.IPv6offsetSrc+net.IPv6len], src)
		copy(ipPkt[ipv6.HeaderLen:], pkPkt.data)
		return len(pkPkt.data) + ipv6.HeaderLen, true
	}
}

func (t *InterceptTun) toPubKeyPacket(pkPkt *PubKeyPacket, ipPkt []byte) bool {
	if len(ipPkt) == 0 {
		return false
	}

	var dst []byte
	var src []byte
	var headerLen int

	switch ipPkt[0] >> 4 {
	case 4:
		if len(ipPkt) < ipv4.HeaderLen {
			return false
		}
		headerLen = ipv4.HeaderLen // header length without extension headers
		dst = ipPkt[wgdevice.IPv4offsetDst : wgdevice.IPv4offsetDst+net.IPv4len]
		src = ipPkt[wgdevice.IPv4offsetSrc : wgdevice.IPv4offsetSrc+net.IPv4len]
	case 6:
		if len(ipPkt) < ipv6.HeaderLen {
			return false
		}
		headerLen = ipv6.HeaderLen
		dst = ipPkt[wgdevice.IPv6offsetDst : wgdevice.IPv6offsetDst+net.IPv6len]
		src = ipPkt[wgdevice.IPv6offsetSrc : wgdevice.IPv6offsetSrc+net.IPv6len]
	default:
		return false
	}
	ipSrc, ok1 := netip.AddrFromSlice(src)
	ipDst, ok2 := netip.AddrFromSlice(dst)
	if !ok1 || !ok2 {
		return false
	}
	t.mu.RLock()
	defer t.mu.Unlock()
	keySrc, ok1 := t.ipToKey[ipSrc]
	keyDst, ok2 := t.ipToKey[ipDst]
	if !ok1 || !ok2 {
		return false
	}
	pkPkt.src = keySrc
	pkPkt.dst = keyDst
	pkPkt.data = append([]byte(nil), ipPkt[headerLen:]...) // deep copy
	return true
}

func (t *InterceptTun) GetInboundPacket() <-chan *PubKeyPacket {
	return t.inboundCh
}

func (t *InterceptTun) SendPubKeyPacket(dst wgdevice.NoisePublicKey, data []byte) {
	t.outboundCh <- &PubKeyPacket{
		src:  t.localKey,
		dst:  dst,
		data: data,
	}
}

// Read implements tun.Device.
func (t *InterceptTun) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	for {
		select {
		case <-t.ctx.Done():
			return 0, net.ErrClosed
		case result, ok := <-t.readCh:
			if !ok {
				return 0, net.ErrClosed
			}
			if result.err != nil {
				return result.n, result.err
			}
			copy(sizes, result.sizes)
			for i := range result.bufs {
				copy(bufs[i][offset:], result.bufs[i][:sizes[i]])
			}
			return len(result.bufs), nil
		case packet, ok := <-t.outboundCh:
			if !ok {
				return 0, net.ErrClosed
			}

			if n, ok := t.toIpPacket(bufs[0][offset:], packet); ok {
				sizes[0] = n
				return 1, nil
			}
			continue // drop silently
		}
	}
}

// Write implements tun.Device.
func (t *InterceptTun) Write(bufs [][]byte, offset int) (int, error) {
	var newBufs [][]byte
	write := 0
	for i := 0; i < len(bufs); i++ {
		packet := bufs[i][offset:]
		var pkPacket PubKeyPacket
		if ok := t.toPubKeyPacket(&pkPacket, packet); ok {
			t.inboundCh <- &pkPacket
			write += 1
		} else {
			newBufs = append(newBufs, bufs[i])
		}
	}
	tunWrite, err := t.inner.Write(newBufs, offset)
	if err != nil {
		return 0, err
	}
	return tunWrite + write, nil
}

func (t *InterceptTun) routineReadFromTUN() {
	defer close(t.readCh)
	for {
		select {
		case <-t.ctx.Done():
			return
		default:
		}

		var (
			batchSize = t.inner.BatchSize()
			bufs      = make([][]byte, batchSize)
			sizes     = make([]int, batchSize)
		)

		for i := range bufs {
			bufs[i] = make([]byte, wgdevice.MaxMessageSize)
		}

		n, err := t.inner.Read(bufs, sizes, 0)
		t.readCh <- &readResult{
			bufs:  bufs,
			sizes: sizes,
			n:     n,
			err:   err,
		}
		if err == net.ErrClosed {
			return
		}
	}
}
