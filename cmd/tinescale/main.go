package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

type InterceptingBind struct {
	inner conn.Bind
}

func (b *InterceptingBind) Open(port uint16) (fns []conn.ReceiveFunc, actualPort uint16, err error) {
	fns, actualPort, err = b.inner.Open(port)
	if err != nil {
		return fns, actualPort, err
	}

	wrapped := make([]conn.ReceiveFunc, len(fns))
	for i, fn := range fns {
		wrapped[i] = func(buffs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
			n, err := fn(buffs, sizes, eps)
			for j := range n {
				fmt.Printf("[Encrypted IN] (%d bytes) from %s: %x\n", sizes[j], eps[j].DstToString(), buffs[j][:sizes[j]])
			}
			return n, err
		}
	}

	return wrapped, actualPort, nil
}

func (b *InterceptingBind) Close() error {
	return b.inner.Close()
}

func (b *InterceptingBind) BatchSize() int {
	return b.inner.BatchSize()
}

func (b *InterceptingBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	return b.inner.ParseEndpoint(s)
}

func (b *InterceptingBind) SetMark(value uint32) error {
	return b.inner.SetMark(value)
}

func (b *InterceptingBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	// AFTER encryption (outbound encrypted)
	for _, buf := range bufs {
		fmt.Printf("[Encrypted OUT] (%d bytes) to %s\n", len(buf), ep.DstToString())
	}
	return b.inner.Send(bufs, ep)
}

func main() {
	ipcPath := flag.String("ipc", "", "Path to WireGuard ipc file")
	flag.Parse()

	if *ipcPath == "" {
		log.Fatal("Missing required --ipc argument")
	}

	// Read ipc file
	ipcBytes, err := os.ReadFile(*ipcPath)
	if err != nil {
		log.Fatalf("Failed to read config file: %v", err)
	}
	ipc := string(ipcBytes)

	// Open TUN device
	const name = "wg0"
	tunDev, err := tun.CreateTUN(name, 1420)
	if err != nil {
		log.Fatal("TUN open error:", err)
	}
	fmt.Println("Opened TUN:", name)

	// Start embedded WireGuard engine
	logger := device.NewLogger(device.LogLevelVerbose, fmt.Sprintf("[%s] ", name))
	bind := &InterceptingBind{inner: conn.NewDefaultBind()}
	dev := device.NewDevice(tunDev, bind, logger)
	defer dev.Close()

	// Configure wireguard interface
	if err := dev.IpcSet(ipc); err != nil {
		log.Fatal("WireGuard config failed:", err)
	}
	dev.Up()

	// Print configuration
	out, err := dev.IpcGet()
	if err != nil {
		log.Fatal("WireGuard config failed:", err)
	}
	log.Println(out)

	// Read decrypted traffic
	bufs := make([][]byte, 8)
	sizes := make([]int, 8)
	for i := range bufs {
		bufs[i] = make([]byte, 65535)
	}

	for {
		n, err := tunDev.Read(bufs, sizes, 0)
		if err == io.EOF {
			break
		} else if err != nil {
			log.Println("Read error:", err)
			continue
		}
		for i := range n {
			fmt.Printf("Packet %d (%d bytes): %x\n", i, sizes[i], bufs[i][:sizes[i]])
		}
	}
}
