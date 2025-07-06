package device

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
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
	inner         io.Reader
	scanner       *bufio.Scanner
	device        *Device
	bufferedBytes []byte
	ipcErr        *IPCError
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

func (ir *InterceptReader) handleLine(key, value string) (bool, error) {
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

func (ir *InterceptReader) Read(p []byte) (int, error) {

	if ir.scanner == nil {
		ir.scanner = bufio.NewScanner(ir.inner)
	}

	// Serve from buffered lines if any
	if len(ir.bufferedBytes) > 0 {
		return ir.readBufferedBytes(p)
	}

	for ir.scanner.Scan() {
		line := ir.scanner.Text()
		ir.device.log.Verbosef("UAPI: read %s", line)
		if line == "" {
			ir.bufferedBytes = append(ir.scanner.Bytes(), '\n')
			return ir.readBufferedBytes(p)
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			ir.bufferedBytes = append(ir.scanner.Bytes(), '\n')
			return ir.readBufferedBytes(p)
		}
		found, err := ir.handleLine(key, value)
		if err != nil {
			return 0, err
		}
		if !found {
			ir.bufferedBytes = append(ir.scanner.Bytes(), '\n')
			return ir.readBufferedBytes(p)
		}
	}

	if err := ir.scanner.Err(); err != nil {
		ir.ipcErr = ipcErrorf(ipc.IpcErrorIO, "failed to read input: %w", err)
	}
	return 0, ir.ipcErr
}

func (device *Device) IpcSetOperation(r io.Reader) error {
	device.ipcMutex.Lock()
	defer device.ipcMutex.Unlock()
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
