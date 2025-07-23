package helper

import (
	"crypto/sha256"
	"net/netip"

	"golang.org/x/crypto/curve25519"
	wgdevice "golang.zx2c4.com/wireguard/device"
)

func PublicKey(sk *wgdevice.NoisePrivateKey) (pk wgdevice.NoisePublicKey) {
	apk := (*[wgdevice.NoisePublicKeySize]byte)(&pk)
	ask := (*[wgdevice.NoisePrivateKeySize]byte)(sk)
	curve25519.ScalarBaseMult(apk, ask)
	return
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
