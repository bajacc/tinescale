package device

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"

	wgdevice "golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/ipc"
)

type IPCError struct {
	code int64 // error code
	err  error // underlying/wrapped error
}

func (s IPCError) Error() string {
	return fmt.Sprintf("IPC error %d: %v", s.code, s.err)
}

func (s IPCError) Unwrap() error {
	return s.err
}

func (s IPCError) ErrorCode() int64 {
	return s.code
}

func ipcErrorf(code int64, msg string, args ...any) *IPCError {
	return &IPCError{code: code, err: fmt.Errorf(msg, args...)}
}

func ipcError(code int64, err error) *IPCError {
	return &IPCError{code: code, err: err}
}

var byteBufferPool = &sync.Pool{
	New: func() any { return new(bytes.Buffer) },
}

type InterceptReader struct {
	scanner      *bufio.Scanner
	device       *Device
	currentPeer  *Peer
	deviceConfig bool

	bufferedBytes []byte
	ipcErr        *IPCError
}

func NewInterceptReader(r io.Reader, device *Device) *InterceptReader {
	return &InterceptReader{
		scanner:      bufio.NewScanner(r),
		device:       device,
		deviceConfig: true,
	}
}

func (ir *InterceptReader) Read(p []byte) (int, error) {

	// Serve from buffered lines if any
	if len(ir.bufferedBytes) > 0 {
		return ir.readBufferedBytes(p)
	}

	for ir.scanner.Scan() {
		line := ir.scanner.Text()
		ir.device.log.Verbosef("UAPI: read %s", line)
		if line == "" {
			return ir.bufferBytesAndRead(p)
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return ir.bufferBytesAndRead(p)
		}
		n, err := ir.handleLine(key, value, p)
		if err != nil || n != 0 {
			return n, err
		}
	}

	if err := ir.scanner.Err(); err != nil {
		ir.ipcErr = ipcErrorf(ipc.IpcErrorIO, "failed to read input: %w", err)
	}
	return 0, ir.ipcErr
}

func (ir *InterceptReader) readBufferedBytes(p []byte) (int, error) {
	if len(ir.bufferedBytes) == 0 {
		return 0, io.EOF
	}

	n := copy(p, ir.bufferedBytes)
	if len(p) >= len(ir.bufferedBytes) {
		// Entire buffer fits
		ir.bufferedBytes = nil
	} else {
		// Partial copy, leave the rest for next read
		ir.bufferedBytes = ir.bufferedBytes[n:]
	}
	return n, nil
}

func (ir *InterceptReader) bufferBytesAndRead(p []byte) (int, error) {
	ir.bufferedBytes = append(ir.scanner.Bytes(), '\n')
	return ir.readBufferedBytes(p)
}

func (ir *InterceptReader) handleLine(key, value string, p []byte) (int, error) {
	if key == "public_key" {
		if ir.deviceConfig {
			ir.deviceConfig = false
		}

		// Load/create the peer we are now configuring.
		return ir.handlePublicKeyLine(peer, value, p)
	}

	var err error
	if ir.deviceConfig {
		err = ir.handleDeviceLine(key, value)
	} else {
		err = ir.handlePeerLine(peer, key, value)
	}
	if err != nil {
		return err
	}

	switch key {
	case "replace_stun_servers":
		if value != "true" {
			ir.ipcErr = ipcErrorf(ipc.IpcErrorInvalid, "failed to replace stun_server, invalid value: %v", value)
			return true, ir.ipcErr
		}
		ir.device.log.Verbosef("UAPI: Removing all stun_server")
		ir.device.stunServers.Lock()
		defer ir.device.stunServers.Unlock()
		ir.device.stunServers.endpoints = nil

	case "replace_derp_servers":
		if value != "true" {
			ir.ipcErr = ipcErrorf(ipc.IpcErrorInvalid, "failed to replace derp_server, invalid value: %v", value)
			return true, ir.ipcErr
		}
		ir.device.log.Verbosef("UAPI: Removing all derp_server")
		ir.device.derpServers.Lock()
		defer ir.device.derpServers.Unlock()
		ir.device.derpServers.endpoints = nil

	case "stun_server":
		add := true
		verb := "Adding"
		if len(value) > 0 && value[0] == '-' {
			add = false
			verb = "Removing"
			value = value[1:]
		}
		ir.device.log.Verbosef("UAPI: %s stun_server", verb)

		endpoint, err := ir.device.net.bind.ParseEndpoint(value)
		if err != nil {
			ir.ipcErr = ipcErrorf(ipc.IpcErrorInvalid, "failed to set stun_server %v: %w", value, err)
			return true, ir.ipcErr
		}
		if add {
			ir.device.stunServers.Lock()
			defer ir.device.stunServers.Unlock()
			ir.device.stunServers.endpoints = append(ir.device.stunServers.endpoints, endpoint)
		} else {
			ir.device.removeStunServer(endpoint)
		}

	case "derp_server":
		add := true
		verb := "Adding"
		if len(value) > 0 && value[0] == '-' {
			add = false
			verb = "Removing"
			value = value[1:]
		}
		ir.device.log.Verbosef("UAPI: %s derp_server", verb)

		endpoint, err := ir.device.net.bind.ParseEndpoint(value)
		if err != nil {
			ir.ipcErr = ipcErrorf(ipc.IpcErrorInvalid, "failed to set derp_server %v: %w", value, err)
			return true, ir.ipcErr
		}

		if add {
			ir.device.derpServers.Lock()
			defer ir.device.derpServers.Unlock()
			ir.device.derpServers.endpoints = append(ir.device.derpServers.endpoints, endpoint)
		} else {
			ir.device.removeDerpServer(endpoint)
		}

	default:
		return false, nil
	}
	return true, nil
}

func (device *Device) IpcSetOperation(r io.Reader) error {
	device.ipcMutex.Lock()
	defer device.ipcMutex.Unlock()

	peer := new(ipcSetPeer)
	deviceConfig := true

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			// Blank line means terminate operation.
			peer.handlePostConfig()
			return nil
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return ipcErrorf(ipc.IpcErrorProtocol, "failed to parse line %q", line)
		}

		if key == "public_key" {
			if deviceConfig {
				deviceConfig = false
			}
			peer.handlePostConfig()
			// Load/create the peer we are now configuring.
			err := device.handlePublicKeyLine(peer, value)
			if err != nil {
				return err
			}
			continue
		}

		var err error
		if deviceConfig {
			err = device.handleDeviceLine(key, value)
		} else {
			err = device.handlePeerLine(peer, key, value)
		}
		if err != nil {
			return err
		}
	}
	peer.handlePostConfig()

	if err := scanner.Err(); err != nil {
		return ipcErrorf(ipc.IpcErrorIO, "failed to read input: %w", err)
	}
	return nil

	//
	ir := InterceptReader{inner: r, device: device}

	err := device.inner.IpcSetOperation(&ir)
	if ir.ipcErr != nil {
		return ir.ipcErr
	}
	var status *wgdevice.IPCError
	if err != nil && !errors.As(err, &status) {
		// shouldn't happen
		return ipcErrorf(ipc.IpcErrorUnknown, "other UAPI error: %w", err)
	}
	if status != nil {
		return ipcError(status.ErrorCode(), status.Unwrap())
	}

	buf, err := device.inner.IpcGet()
	if err != nil {
		return err
	}

	err = device.updateWGInfo(strings.NewReader(buf))
	if err != nil {
		return ipcErrorf(ipc.IpcErrorUnknown, "could not parse get=1: %w", err)
	}
	return nil
}

func (device *Device) handleDeviceLine(key, value string) error {
	switch key {
	case "private_key":
		var sk NoisePrivateKey
		err := sk.FromMaybeZeroHex(value)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to set private_key: %w", err)
		}
		device.log.Verbosef("UAPI: Updating private key")
		device.SetPrivateKey(sk)

	case "listen_port":
		port, err := strconv.ParseUint(value, 10, 16)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to parse listen_port: %w", err)
		}

		// update port and rebind
		device.log.Verbosef("UAPI: Updating listen port")

		device.net.Lock()
		device.net.port = uint16(port)
		device.net.Unlock()

		if err := device.BindUpdate(); err != nil {
			return ipcErrorf(ipc.IpcErrorPortInUse, "failed to set listen_port: %w", err)
		}

	case "fwmark":
		mark, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "invalid fwmark: %w", err)
		}

		device.log.Verbosef("UAPI: Updating fwmark")
		if err := device.BindSetMark(uint32(mark)); err != nil {
			return ipcErrorf(ipc.IpcErrorPortInUse, "failed to update fwmark: %w", err)
		}

	case "replace_peers":
		if value != "true" {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to set replace_peers, invalid value: %v", value)
		}
		device.log.Verbosef("UAPI: Removing all peers")
		device.RemoveAllPeers()

	default:
		return ipcErrorf(ipc.IpcErrorInvalid, "invalid UAPI device key: %v", key)
	}

	return nil
}

// An ipcSetPeer is the current state of an IPC set operation on a peer.
type ipcSetPeer struct {
	*Peer        // Peer is the current peer being operated on
	dummy   bool // dummy reports whether this peer is a temporary, placeholder peer
	created bool // new reports whether this is a newly created peer
	pkaOn   bool // pkaOn reports whether the peer had the persistent keepalive turn on
}

func (peer *ipcSetPeer) handlePostConfig() {
	if peer.Peer == nil || peer.dummy {
		return
	}
	if peer.created {
		peer.endpoint.disableRoaming = peer.device.net.brokenRoaming && peer.endpoint.val != nil
	}
	if peer.device.isUp() {
		peer.Start()
		if peer.pkaOn {
			peer.SendKeepalive()
		}
		peer.SendStagedPackets()
	}
}

func (device *Device) handlePublicKeyLine(peer *ipcSetPeer, value string) error {
	// Load/create the peer we are configuring.
	var publicKey NoisePublicKey
	err := publicKey.FromHex(value)
	if err != nil {
		return ipcErrorf(ipc.IpcErrorInvalid, "failed to get peer by public key: %w", err)
	}

	// Ignore peer with the same public key as this device.
	device.staticIdentity.RLock()
	peer.dummy = device.staticIdentity.publicKey.Equals(publicKey)
	device.staticIdentity.RUnlock()

	if peer.dummy {
		peer.Peer = &Peer{}
	} else {
		peer.Peer = device.LookupPeer(publicKey)
	}

	peer.created = peer.Peer == nil
	if peer.created {
		peer.Peer, err = device.NewPeer(publicKey)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to create new peer: %w", err)
		}
		device.log.Verbosef("%v - UAPI: Created", peer.Peer)
	}
	return nil
}

func (device *Device) handlePeerLine(peer *ipcSetPeer, key, value string) error {
	switch key {
	case "update_only":
		// allow disabling of creation
		if value != "true" {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to set update only, invalid value: %v", value)
		}
		if peer.created && !peer.dummy {
			device.RemovePeer(peer.handshake.remoteStatic)
			peer.Peer = &Peer{}
			peer.dummy = true
		}

	case "remove":
		// remove currently selected peer from device
		if value != "true" {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to set remove, invalid value: %v", value)
		}
		if !peer.dummy {
			device.log.Verbosef("%v - UAPI: Removing", peer.Peer)
			device.RemovePeer(peer.handshake.remoteStatic)
		}
		peer.Peer = &Peer{}
		peer.dummy = true

	case "preshared_key":
		device.log.Verbosef("%v - UAPI: Updating preshared key", peer.Peer)

		peer.handshake.mutex.Lock()
		err := peer.handshake.presharedKey.FromHex(value)
		peer.handshake.mutex.Unlock()

		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to set preshared key: %w", err)
		}

	case "endpoint":
		device.log.Verbosef("%v - UAPI: Updating endpoint", peer.Peer)
		endpoint, err := device.net.bind.ParseEndpoint(value)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to set endpoint %v: %w", value, err)
		}
		peer.endpoint.Lock()
		defer peer.endpoint.Unlock()
		peer.endpoint.val = endpoint

	case "persistent_keepalive_interval":
		device.log.Verbosef("%v - UAPI: Updating persistent keepalive interval", peer.Peer)

		secs, err := strconv.ParseUint(value, 10, 16)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to set persistent keepalive interval: %w", err)
		}

		old := peer.persistentKeepaliveInterval.Swap(uint32(secs))

		// Send immediate keepalive if we're turning it on and before it wasn't on.
		peer.pkaOn = old == 0 && secs != 0

	case "replace_allowed_ips":
		device.log.Verbosef("%v - UAPI: Removing all allowedips", peer.Peer)
		if value != "true" {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to replace allowedips, invalid value: %v", value)
		}
		if peer.dummy {
			return nil
		}
		device.allowedips.RemoveByPeer(peer.Peer)

	case "allowed_ip":
		add := true
		verb := "Adding"
		if len(value) > 0 && value[0] == '-' {
			add = false
			verb = "Removing"
			value = value[1:]
		}
		device.log.Verbosef("%v - UAPI: %s allowedip", peer.Peer, verb)
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to set allowed ip: %w", err)
		}
		if peer.dummy {
			return nil
		}
		if add {
			device.allowedips.Insert(prefix, peer.Peer)
		} else {
			device.allowedips.Remove(prefix, peer.Peer)
		}

	case "protocol_version":
		if value != "1" {
			return ipcErrorf(ipc.IpcErrorInvalid, "invalid protocol version: %v", value)
		}

	default:
		return ipcErrorf(ipc.IpcErrorInvalid, "invalid UAPI peer key: %v", key)
	}

	return nil
}

func (device *Device) updateWGInfo(r io.Reader) error {

	device.peers.Lock()
	defer device.peers.Unlock()

	keyMap := map[wgdevice.NoisePublicKey]*Peer{}
	var currentPeer *Peer

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}

		switch key {
		case "private_key":
			device.staticIdentity.Lock()
			defer device.staticIdentity.Unlock()
			if err := device.staticIdentity.privateKey.FromMaybeZeroHex(value); err != nil {
				return err
			}
			device.staticIdentity.publicKey = publicKey(&device.staticIdentity.privateKey)
		case "public_key":
			var publicKey wgdevice.NoisePublicKey
			if err := publicKey.FromHex(value); err != nil {
				return err
			}
			val, ok := device.peers.keyMap[publicKey]
			if ok {
				currentPeer = val
			} else {
				currentPeer = new(Peer)
			}
			keyMap[publicKey] = currentPeer

		case "endpoint":
			endpoint, err := device.net.bind.ParseEndpoint(value)
			if err != nil {
				return err
			}
			currentPeer.endpoint.Lock()
			currentPeer.endpoint.val = endpoint
			currentPeer.endpoint.Unlock()
		}
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	device.peers.keyMap = keyMap

	return nil
}

func (device *Device) IpcGetOperation(w io.Writer) error {
	device.ipcMutex.RLock()
	defer device.ipcMutex.RUnlock()

	buf := byteBufferPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer byteBufferPool.Put(buf)
	sendf := func(format string, args ...any) {
		fmt.Fprintf(buf, format, args...)
		buf.WriteByte('\n')
	}

	func() {
		// lock required resources
		device.stunServers.RLock()
		defer device.stunServers.RUnlock()

		device.derpServers.RLock()
		defer device.derpServers.RUnlock()

		// serialize device related values
		for _, endpoint := range device.stunServers.endpoints {
			sendf("stun_server=%s", endpoint.DstToString())
		}
		for _, endpoint := range device.derpServers.endpoints {
			sendf("derp_server=%s", endpoint.DstToString())
		}
	}()

	// send lines (does not require resource locks)
	if _, err := w.Write(buf.Bytes()); err != nil {
		return ipcErrorf(ipc.IpcErrorIO, "failed to write output: %w", err)
	}

	err := device.inner.IpcGetOperation(w)
	var status *wgdevice.IPCError
	if err != nil && !errors.As(err, &status) {
		// shouldn't happen
		return ipcErrorf(ipc.IpcErrorUnknown, "other UAPI error: %w", err)
	}
	if status != nil {
		return ipcError(status.ErrorCode(), status.Unwrap())
	}
	return nil

}

func (device *Device) IpcHandle(socket net.Conn) {
	defer socket.Close()

	buffered := func(s io.ReadWriter) *bufio.ReadWriter {
		reader := bufio.NewReader(s)
		writer := bufio.NewWriter(s)
		return bufio.NewReadWriter(reader, writer)
	}(socket)

	for {
		op, err := buffered.ReadString('\n')
		if err != nil {
			return
		}

		// handle operation
		switch op {
		case "set=1\n":
			err = device.IpcSetOperation(buffered.Reader)
		case "get=1\n":
			var nextByte byte
			nextByte, err = buffered.ReadByte()
			if err != nil {
				return
			}
			if nextByte != '\n' {
				err = ipcErrorf(ipc.IpcErrorInvalid, "trailing character in UAPI get: %q", nextByte)
				break
			}
			err = device.IpcGetOperation(buffered.Writer)
		default:
			device.log.Errorf("invalid UAPI operation: %v", op)
			return
		}

		// write status
		var status *IPCError
		if err != nil && !errors.As(err, &status) {
			// shouldn't happen
			status = ipcErrorf(ipc.IpcErrorUnknown, "other UAPI error: %w", err)
		}
		if status != nil {
			device.log.Errorf("%v", status)
			fmt.Fprintf(buffered, "errno=%d\n\n", status.ErrorCode())
		} else {
			fmt.Fprintf(buffered, "errno=0\n\n")
		}
		buffered.Flush()
	}
}
