package device

import (
	"fmt"
	"net/netip"

	"go4.org/mem"
	"golang.zx2c4.com/wireguard/conn"
	wgdevice "golang.zx2c4.com/wireguard/device"
	"tailscale.com/derp"
	"tailscale.com/types/key"
)

type Bind struct {
	inner  conn.Bind
	device *Device
}

type Endpoint struct {
	origPubKey wgdevice.NoisePublicKey
}

func NewBind(inner conn.Bind, device *Device) *Bind {
	return &Bind{
		inner:  inner,
		device: device,
	}
}

// ClearSrc implements conn.Endpoint.
func (e *Endpoint) ClearSrc() {}

// DstIP implements conn.Endpoint.
func (e *Endpoint) DstIP() netip.Addr {
	// Generate a deterministic IP from the public key for rate limiting
	// Use the first 4 bytes of the public key as an IPv4 address in the 10.0.0.0/8 range
	if len(e.origPubKey) >= 4 {
		return netip.AddrFrom4([4]byte{10, e.origPubKey[0], e.origPubKey[1], e.origPubKey[2]})
	}
	return netip.Addr{}
}

// DstToBytes implements conn.Endpoint.
func (e *Endpoint) DstToBytes() []byte {
	return e.origPubKey[:]
}

// DstToString implements conn.Endpoint.
func (e *Endpoint) DstToString() string {
	return fmt.Sprintf("tinescale:%x", e.origPubKey[:8])
}

// SrcIP implements conn.Endpoint.
func (e *Endpoint) SrcIP() netip.Addr {
	return netip.Addr{}
}

// SrcToString implements conn.Endpoint.
func (e *Endpoint) SrcToString() string {
	return ""
}

func (b *Bind) ParseEndpoint(s string) (conn.Endpoint, error) {
	var publicKey wgdevice.NoisePublicKey
	err := publicKey.FromHex(s)
	if err != nil {
		return nil, err
	}
	return &Endpoint{
		origPubKey: publicKey,
	}, nil
}

func (b *Bind) ParseInnerEndpoint(s string) (conn.Endpoint, error) {
	return b.inner.ParseEndpoint(s)
}

func (b *Bind) BatchSize() int {
	return b.inner.BatchSize()
}

func (b *Bind) Close() error {
	return b.inner.Close()
}

func (b *Bind) SetMark(mark uint32) error {
	return b.inner.SetMark(mark)
}

func (b *Bind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	// fns is the receive functions (UAPI and STUN endpoints)
	fns, actualPort, err := b.inner.Open(port)
	if err != nil {
		return fns, actualPort, err
	}

	// Add single DERP receive function that handles all DERP clients
	if len(b.device.derp.clients) > 0 {
		derpReceiveFunc := func(bufs [][]byte, sizes []int, eps []conn.Endpoint) (n int, err error) {
			return b.receiveDERPFromAnyClient(bufs, sizes, eps)
		}
		fns = append(fns, derpReceiveFunc)
	}

	return fns, actualPort, err
}

func (b *Bind) receiveDERPNonBlocking(derpClient *Derp, bufs [][]byte, sizes []int, eps []conn.Endpoint) (n int, err error) {
	derpClient.RLock()
	defer derpClient.RUnlock()

	if derpClient.val == nil {
		return 0, nil
	}

	// Process multiple messages up to the buffer limit
	var count int
	maxMsgs := len(bufs)

	for count < maxMsgs {
		// Attempt to receive a message (this may block, but that's expected for ReceiveFunc)
		msg, err := derpClient.val.Recv()
		if err != nil {
			if count > 0 {
				// We got some messages, return them and ignore this error
				break
			}
			return 0, err
		}

		// Type assert to ReceivedPacket
		packet, ok := msg.(*derp.ReceivedPacket)
		if !ok {
			continue // Skip invalid message types
		}

		// Convert NodePublic to NoisePublicKey
		sourceBytes := packet.Source.AppendTo([]byte{})
		var noiseKey wgdevice.NoisePublicKey
		copy(noiseKey[:], sourceBytes)

		// Find the peer endpoint for this message
		b.device.peers.RLock()
		_, peerExists := b.device.peers.keyMap[noiseKey]
		b.device.peers.RUnlock()

		if !peerExists {
			// Unknown peer, ignore message and continue
			continue
		}

		// Check if we have space for this message
		if len(packet.Data) > len(bufs[count]) {
			// Message too large for buffer, skip it
			continue
		}

		// Copy message data to buffer
		copy(bufs[count], packet.Data)
		sizes[count] = len(packet.Data)

		// Set endpoint to the peer's endpoint
		eps[count] = &Endpoint{
			origPubKey: noiseKey,
		}

		count++

		// For now, only process one message per call to avoid blocking too long
		// This can be optimized later if needed
		break
	}

	return count, nil
}

func (b *Bind) receiveDERPFromAnyClient(bufs [][]byte, sizes []int, eps []conn.Endpoint) (n int, err error) {
	b.device.derp.RLock()
	clients := make([]*Derp, len(b.device.derp.clients))
	copy(clients, b.device.derp.clients)
	b.device.derp.RUnlock()

	if len(clients) == 0 {
		return 0, nil
	}

	// Try to receive from the first available client
	// In a more sophisticated implementation, we could use select with channels
	// to receive from any client that has messages available
	for _, client := range clients {
		count, err := b.receiveDERPNonBlocking(client, bufs, sizes, eps)
		if err != nil {
			continue // Try next client
		}
		if count > 0 {
			return count, nil
		}
	}

	// If no clients had messages, block on the first client
	// This ensures the ReceiveFunc blocks as expected by WireGuard
	if len(clients) > 0 {
		return b.receiveDERPNonBlocking(clients[0], bufs, sizes, eps)
	}

	return 0, nil
}

func (b *Bind) Send(bufs [][]byte, endpoint conn.Endpoint) error {
	ep, ok := endpoint.(*Endpoint)
	if !ok {
		return fmt.Errorf("Error Enpoint is not a tinescale endpoint")
	}
	b.device.peers.RLock()
	defer b.device.peers.RUnlock()
	peer, ok := b.device.peers.keyMap[ep.origPubKey]
	if !ok {
		return fmt.Errorf("peer with public key %s not found", ep.origPubKey)
	}

	peer.endpoint.RLock()
	defer peer.endpoint.RUnlock()

	var err error

	// send via uapi configured endpoints
	err = b.inner.Send(bufs, peer.endpoint.uapi)
	if err == nil {
		return nil
	}

	// else send via stun configured endpoints
	for _, stunEndpoint := range peer.endpoint.stun {
		err = b.inner.Send(bufs, stunEndpoint)
		if err == nil {
			return nil
		}
	}

	// else send via DERP
	b.device.derp.RLock()
	defer b.device.derp.RUnlock()
	for _, derpClient := range b.device.derp.clients {
		err = derpClient.Send(bufs, ep.origPubKey)
		if err == nil {
			return nil
		}
	}

	return err
}

func (d *Derp) Send(bufs [][]byte, publicKey wgdevice.NoisePublicKey) error {
	// Convert wgdevice.NoisePublicKey to the key type expected by DERP client
	d.RLock()
	defer d.RUnlock()
	derpKey := key.NodePublicFromRaw32(mem.B(publicKey[:]))

	for _, buf := range bufs {
		if err := d.val.Send(derpKey, buf); err != nil {
			return err
		}
	}
	return nil
}
