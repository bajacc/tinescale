package device

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
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
	scanner *bufio.Scanner
	device  *Device
	log     *wgdevice.Logger

	peerConfig *PeerConfig

	bufferedBytes []byte
	ipcErr        *IPCError
}

type PeerConfig struct {
	publicKey       wgdevice.NoisePublicKey
	publicKeyString string
	ignore          bool
	updateOnly      bool
	remove          bool
	endpoint        *Endpoint
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

func (device *Device) IpcSetOperation(r io.Reader) error {
	device.ipcMutex.Lock()
	defer device.ipcMutex.Unlock()

	ir := NewInterceptReader(r, device)

	err := device.inner.IpcSetOperation(ir)
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

func NewInterceptReader(r io.Reader, device *Device) *InterceptReader {
	return &InterceptReader{
		scanner:    bufio.NewScanner(r),
		device:     device,
		log:        device.log,
		peerConfig: nil,
	}
}

func (ir *InterceptReader) SetPeerFromConfig() error {
	config := ir.peerConfig

	if config == nil {
		return ipcErrorf(ipc.IpcErrorInvalid, "no peer public key set")
	}

	if config.ignore {
		ir.log.Verbosef("UAPI: ignoring peer with public key %s", config.publicKey)
		return nil
	}

	ir.device.peers.Lock()
	defer ir.device.peers.Unlock()
	if config.remove {
		ir.log.Verbosef("UAPI: removing peer with public key %s", config.publicKey)
		delete(ir.device.peers.keyMap, config.publicKey)
		return nil
	}

	if !config.updateOnly {
		ir.log.Verbosef("UAPI: creating peer with public key %s", config.publicKey)
		ir.device.peers.keyMap[config.publicKey] = &Peer{}
	}
	peer := ir.device.peers.keyMap[config.publicKey]

	peer.endpoint.Lock()
	defer peer.endpoint.Unlock()
	peer.endpoint.val = config.endpoint

	// configure the peer endpoint in wireguard device
	// use the public key so that we can find the endpoint later in bind
	ir.bufferedBytes = append(ir.bufferedBytes, fmt.Sprintf("endpoint=%s\n", config.publicKeyString)...)
	return nil
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
		n, err := ir.readKeyValue(key, value, p)
		if err != nil || n != 0 {
			return n, err
		}
	}

	if ir.peerConfig != nil && ir.SetPeerFromConfig() != nil {
		return 0, ir.ipcErr
	}

	if len(ir.bufferedBytes) > 0 {
		return ir.readBufferedBytes(p)
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
	ir.bufferedBytes = append(ir.bufferedBytes, ir.scanner.Bytes()...)
	ir.bufferedBytes = append(ir.bufferedBytes, '\n')
	return ir.readBufferedBytes(p)
}

func (ir *InterceptReader) readKeyValue(key, value string, p []byte) (int, error) {
	if ir.peerConfig != nil {
		return ir.readPeerLine(key, value, p)
	}
	return ir.readDeviceLine(key, value, p)
}

func (ir *InterceptReader) readPublicKey(value string, p []byte) (int, error) {

	if ir.peerConfig != nil && ir.SetPeerFromConfig() != nil {
		return 0, ir.ipcErr
	}
	ir.peerConfig = &PeerConfig{}

	var publicKey wgdevice.NoisePublicKey
	err := publicKey.FromHex(value)
	if err != nil {
		ir.ipcErr = ipcErrorf(ipc.IpcErrorInvalid, "failed to parse public key: %w", err)
		return 0, ir.ipcErr
	}

	// Ignore peer with the same public key as this device.
	ir.device.staticIdentity.RLock()
	ir.peerConfig.ignore = ir.device.staticIdentity.publicKey.Equals(publicKey)
	ir.device.staticIdentity.RUnlock()

	ir.peerConfig.publicKey = publicKey
	ir.peerConfig.publicKeyString = value
	return ir.bufferBytesAndRead(p)
}

func (ir *InterceptReader) readPeerLine(key, value string, p []byte) (int, error) {
	switch key {
	case "update_only":
		// allow disabling of creation TODO
		if value != "true" {
			ir.ipcErr = ipcErrorf(ipc.IpcErrorInvalid, "failed to set update only, invalid value: %v", value)
			return 0, ir.ipcErr
		}
		ir.peerConfig.updateOnly = true
		return ir.bufferBytesAndRead(p)
	case "remove":
		// remove currently selected peer from device TODO
		if value != "true" {
			ir.ipcErr = ipcErrorf(ipc.IpcErrorInvalid, "failed to set remove, invalid value: %v", value)
			return 0, ir.ipcErr
		}
		ir.peerConfig.remove = true
		return ir.bufferBytesAndRead(p)
	case "endpoint":
		ir.log.Verbosef("%v - UAPI: IGNORE Updating endpoint", ir.peerConfig.publicKey)
		return 0, nil
	default:
		return ir.bufferBytesAndRead(p)
	}
}

func (ir *InterceptReader) readDeviceLine(key, value string, p []byte) (int, error) {
	switch key {
	case "public_key":
		return ir.readPublicKey(value, p)
	case "replace_stun_servers":
		if value != "true" {
			ir.ipcErr = ipcErrorf(ipc.IpcErrorInvalid, "failed to replace stun_server, invalid value: %v", value)
			return 0, ir.ipcErr
		}
		ir.device.log.Verbosef("UAPI: Removing all stun_server")
		ir.device.stunServers.Lock()
		defer ir.device.stunServers.Unlock()
		ir.device.stunServers.endpoints = nil
		return 0, nil

	case "replace_derp_servers":
		if value != "true" {
			ir.ipcErr = ipcErrorf(ipc.IpcErrorInvalid, "failed to replace derp_server, invalid value: %v", value)
			return 0, ir.ipcErr
		}
		ir.device.log.Verbosef("UAPI: Removing all derp_server")
		ir.device.derpServers.Lock()
		defer ir.device.derpServers.Unlock()
		ir.device.derpServers.endpoints = nil
		return 0, nil

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
			return 0, ir.ipcErr
		}
		if add {
			ir.device.stunServers.Lock()
			defer ir.device.stunServers.Unlock()
			ir.device.stunServers.endpoints = append(ir.device.stunServers.endpoints, endpoint)
		} else {
			ir.device.removeStunServer(endpoint)
		}
		return 0, nil

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
			return 0, ir.ipcErr
		}

		if add {
			ir.device.derpServers.Lock()
			defer ir.device.derpServers.Unlock()
			ir.device.derpServers.endpoints = append(ir.device.derpServers.endpoints, endpoint)
		} else {
			ir.device.removeDerpServer(endpoint)
		}
		return 0, nil
	case "private_key":
		var sk wgdevice.NoisePrivateKey
		err := sk.FromMaybeZeroHex(value)
		if err != nil {
			ir.ipcErr = ipcErrorf(ipc.IpcErrorInvalid, "failed to set private_key: %w", err)
			return 0, ir.ipcErr
		}
		ir.log.Verbosef("UAPI: Updating private key")
		ir.device.staticIdentity.Lock()
		defer ir.device.staticIdentity.Unlock()
		ir.device.staticIdentity.privateKey = sk
		ir.device.staticIdentity.publicKey = publicKey(&sk)
		return ir.bufferBytesAndRead(p)
	case "listen_port":
		port, err := strconv.ParseUint(value, 10, 16)
		if err != nil {
			ir.ipcErr = ipcErrorf(ipc.IpcErrorInvalid, "failed to parse listen_port: %w", err)
			return 0, ir.ipcErr
		}
		ir.device.listenPort.Lock()
		defer ir.device.listenPort.Unlock()
		ir.device.listenPort.val = uint16(port)
		return ir.bufferBytesAndRead(p)
	case "replace_peers":
		if value != "true" {
			ir.ipcErr = ipcErrorf(ipc.IpcErrorInvalid, "failed to set replace_peers, invalid value: %v", value)
			return 0, ir.ipcErr
		}
		ir.device.peers.Lock()
		defer ir.device.peers.Unlock()
		ir.device.peers.keyMap = make(map[wgdevice.NoisePublicKey]*Peer)
		return ir.bufferBytesAndRead(p)
	default:
		return ir.bufferBytesAndRead(p)
	}
}
