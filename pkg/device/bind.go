package device

import (
	"golang.zx2c4.com/wireguard/conn"
)

type Bind struct {
	inner  conn.Bind
	device DeviceInterface
}

func (b *Bind) Open(port uint16) (fns []conn.ReceiveFunc, actualPort uint16, err error) {

}
func (b *Bind) Close() error {

}
func (b *Bind) SetMark(mark uint32) error {

}
func (b *Bind) Send(bufs [][]byte, ep conn.Endpoint) error {

}
func (b *Bind) ParseEndpoint(s string) (conn.Endpoint, error) {

}
func (b *Bind) BatchSize() int {

}
