package device

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"

	"golang.zx2c4.com/wireguard/conn"
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
	endpoint        conn.Endpoint
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
		device.stun.RLock()
		defer device.stun.RUnlock()

		// serialize device related values
		for _, client := range device.stun.clients {
			sendf("stun_server=%s", client.addr)
		}
		for _, addr := range device.derpPool.GetAddresses() {
			sendf("derp_server=%s", addr)
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

func (ir *InterceptReader) SetPeerFromConfig() {
	config := ir.peerConfig

	if config == nil {
		return
	}

	if config.ignore {
		ir.log.Verbosef("UAPI(tinescale): ignoring peer with public key %s", config.publicKeyString)
		return
	}

	ir.device.peers.Lock()
	defer ir.device.peers.Unlock()
	if config.remove {
		ir.log.Verbosef("UAPI(tinescale): removing peer with public key %s", config.publicKeyString)
		delete(ir.device.peers.keyMap, config.publicKey)
		return
	}

	if !config.updateOnly {
		ir.log.Verbosef("UAPI(tinescale): creating peer with public key %s", config.publicKeyString)
		ir.device.peers.keyMap[config.publicKey] = &Peer{}
	}
	peer := ir.device.peers.keyMap[config.publicKey]

	func() {
		peer.endpoint.Lock()
		defer peer.endpoint.Unlock()
		peer.endpoint.uapi = config.endpoint
	}()

	// configure the peer endpoint in wireguard device
	// use the public key so that we can find the endpoint later in bind
	endpointLine := fmt.Sprintf("endpoint=%s\n", config.publicKeyString)
	ir.log.Verbosef("UAPI(tinescale): send endpoint line %s", endpointLine)
	ir.bufferedBytes = append(ir.bufferedBytes, endpointLine...)
	ir.peerConfig = nil
}

func (ir *InterceptReader) Read(p []byte) (int, error) {

	// Serve from buffered lines if any
	if len(ir.bufferedBytes) > 0 {
		return ir.readBufferedBytes(p)
	}

	for ir.scanner.Scan() {
		line := ir.scanner.Text()
		ir.device.log.Verbosef("UAPI(tinescale): read %s", line)
		if line == "" {
			ir.SetPeerFromConfig()
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

	ir.SetPeerFromConfig()
	if len(ir.bufferedBytes) > 0 {
		return ir.readBufferedBytes(p)
	}

	if err := ir.scanner.Err(); err != nil {
		ir.ipcErr = ipcErrorf(ipc.IpcErrorIO, "failed to read input: %v", err)
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

	// set the previous peer config if any
	ir.SetPeerFromConfig()

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
		ir.log.Verbosef("UAPI(tinescale): Registering endpoint")
		ep, err := ir.device.net.bind.ParseInnerEndpoint(value)
		if err != nil {
			ir.ipcErr = ipcErrorf(ipc.IpcErrorInvalid, "failed to parse endpoint: %w", err)
			return 0, ir.ipcErr
		}
		ir.peerConfig.endpoint = ep
		// do not propagate endpoint to wireguard device yet
		return 0, nil
	default:
		ir.log.Verbosef("UAPI(tinescale): peer command '%s=%s'", key, value)
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
		ir.device.log.Verbosef("UAPI(tinescale): Removing all stun_server")
		ir.device.stun.Lock()
		defer ir.device.stun.Unlock()
		ir.device.stun.clients = nil
		return 0, nil
	case "replace_derp_servers":
		if value != "true" {
			ir.ipcErr = ipcErrorf(ipc.IpcErrorInvalid, "failed to replace derp_server, invalid value: %v", value)
			return 0, ir.ipcErr
		}
		ir.device.log.Verbosef("UAPI(tinescale): Removing all derp_server")
		ir.device.derpPool.Clear()
		return 0, nil
	case "stun_server":
		raddr, err := net.ResolveUDPAddr("udp", value)
		if err != nil {
			ir.ipcErr = ipcErrorf(ipc.IpcErrorInvalid, "failed to resolve stun_server address %v: %w", value, err)
			return 0, ir.ipcErr
		}

		conn, err := net.DialUDP("udp", nil, raddr)
		if err != nil {
			ir.ipcErr = ipcErrorf(ipc.IpcErrorInvalid, "failed to dial stun_server %v: %w", value, err)
			return 0, ir.ipcErr
		}
		ir.log.Verbosef("UAPI(tinescale): Adding stun_server")
		ir.device.stun.Lock()
		defer ir.device.stun.Unlock()
		stun := &Stun{
			conn: conn,
			addr: value,
		}
		ir.device.stun.clients = append(ir.device.stun.clients, stun)
		return 0, nil
	case "derp_server":
		_, err := url.Parse(value)
		if err != nil {
			ir.ipcErr = ipcErrorf(ipc.IpcErrorInvalid, "failed to set derp_server %v: %w", value, err)
			return 0, ir.ipcErr
		}
		ir.device.staticIdentity.RLock()
		privateKey := ir.device.staticIdentity.privateKey
		ir.device.staticIdentity.RUnlock()
		if privateKey.IsZero() {
			ir.ipcErr = ipcErrorf(ipc.IpcErrorInvalid, "failed to set derp_server %v: private key not set yet", value)
			return 0, ir.ipcErr
		}
		ir.device.derpPool.AddDerpClient(privateKey, value)
		return 0, nil
	case "private_key":
		var sk wgdevice.NoisePrivateKey
		err := sk.FromMaybeZeroHex(value)
		if err != nil {
			ir.ipcErr = ipcErrorf(ipc.IpcErrorInvalid, "failed to set private_key: %w", err)
			return 0, ir.ipcErr
		}
		ir.log.Verbosef("UAPI(tinescale): Updating private key")
		ir.device.staticIdentity.Lock()
		defer ir.device.staticIdentity.Unlock()
		ir.device.staticIdentity.privateKeyHex = value
		ir.device.staticIdentity.privateKey = sk
		ir.device.staticIdentity.publicKey = publicKey(&sk)
		return ir.bufferBytesAndRead(p)
	case "listen_port":
		port, err := strconv.ParseUint(value, 10, 16)
		if err != nil {
			ir.ipcErr = ipcErrorf(ipc.IpcErrorInvalid, "failed to parse listen_port: %w", err)
			return 0, ir.ipcErr
		}
		ir.log.Verbosef("UAPI(tinescale): Updating listen port to %d", port)
		ir.device.listenPort.Lock()
		defer ir.device.listenPort.Unlock()
		ir.device.listenPort.val = uint16(port)
		return ir.bufferBytesAndRead(p)
	case "replace_peers":
		if value != "true" {
			ir.ipcErr = ipcErrorf(ipc.IpcErrorInvalid, "failed to set replace_peers, invalid value: %v", value)
			return 0, ir.ipcErr
		}
		ir.log.Verbosef("UAPI(tinescale): replace peers")
		ir.device.peers.Lock()
		defer ir.device.peers.Unlock()
		ir.device.peers.keyMap = make(map[wgdevice.NoisePublicKey]*Peer)
		return ir.bufferBytesAndRead(p)
	default:
		ir.log.Verbosef("UAPI(tinescale): other command '%s=%s'", key, value)
		return ir.bufferBytesAndRead(p)
	}
}
