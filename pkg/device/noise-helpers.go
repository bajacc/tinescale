package device

import (
	"golang.org/x/crypto/curve25519"
	wgdevice "golang.zx2c4.com/wireguard/device"
)

func publicKey(sk *wgdevice.NoisePrivateKey) (pk wgdevice.NoisePublicKey) {
	apk := (*[wgdevice.NoisePublicKeySize]byte)(&pk)
	ask := (*[wgdevice.NoisePrivateKeySize]byte)(sk)
	curve25519.ScalarBaseMult(apk, ask)
	return
}
