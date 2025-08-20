//go:generate protoc --go_out=paths=source_relative:. securemsg.proto
package securemsg

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"sync"
	"time"

	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	wgdevice "golang.zx2c4.com/wireguard/device"
	"google.golang.org/protobuf/proto"
)

const (
	noiseConstruction = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
	noiseIdentifier   = "WireGuard v1 zx2c4 Jason@zx2c4.com"
)

type SecureMsg interface {
	SetPrivateKey(key wgdevice.NoisePrivateKey)
	AddPeerPublicKey(key wgdevice.NoisePublicKey)
	InitiateHandshake(peerPublicKey [32]byte) ([]byte, error)
	HandleNoiseInit(buf []byte) ([]byte, error)
	HandleNoiseResponse(buf []byte) error
	DecryptNoiseTransport(buf []byte) (*UnencryptedMessage, error)
	EncryptNoiseTransport(msg *UnencryptedMessage, peerPublicKey [32]byte) ([]byte, error)
}

type handshakeState struct {
	localEphemeral  [32]byte
	remoteEphemeral [32]byte
	ss              [32]byte
	ee              [32]byte
	ck              [32]byte
	h               [32]byte
	psk             [32]byte
}

type transportState struct {
	sendKey   [32]byte
	recvKey   [32]byte
	sendNonce uint64
	recvNonce uint64
}

type secureMsg struct {
	log           *wgdevice.Logger
	privateKey    [32]byte
	publicKey     [32]byte
	peerPublicKey map[[32]byte]struct{}

	mu         sync.RWMutex
	handshakes map[[32]byte]*handshakeState
	transports map[[32]byte]*transportState
}

func New() SecureMsg {
	return &secureMsg{
		peerPublicKey: make(map[[32]byte]struct{}),
		handshakes:    make(map[[32]byte]*handshakeState),
		transports:    make(map[[32]byte]*transportState),
	}
}

func noiseHash(h []byte, data []byte) []byte {
	hasher, _ := blake2s.New256(nil)
	hasher.Write(h)
	hasher.Write(data)
	return hasher.Sum(nil)
}

func noiseHKDF(ck, input []byte) ([32]byte, [32]byte) {
	hasher, _ := blake2s.New256(nil)
	hasher.Write(ck)
	hasher.Write(input)
	temp := hasher.Sum(nil)

	hasher.Reset()
	hasher.Write(temp)
	hasher.Write([]byte{1})
	ck1 := hasher.Sum(nil)

	hasher.Reset()
	hasher.Write(temp)
	hasher.Write([]byte{2})
	ck2 := hasher.Sum(nil)

	var k1, k2 [32]byte
	copy(k1[:], ck1)
	copy(k2[:], ck2)
	return k1, k2
}

func (s *secureMsg) mixHash(h []byte, data []byte) [32]byte {
	result := noiseHash(h, data)
	var hash [32]byte
	copy(hash[:], result)
	return hash
}

func (s *secureMsg) mixKey(ck []byte, input []byte) ([32]byte, [32]byte) {
	return noiseHKDF(ck, input)
}

func (s *secureMsg) encryptAndHash(hs *handshakeState, plaintext []byte) []byte {
	if len(plaintext) == 0 {
		hs.h = s.mixHash(hs.h[:], nil)
		return nil
	}
	aead, _ := chacha20poly1305.New(hs.ck[:])
	ciphertext := aead.Seal(nil, make([]byte, 12), plaintext, hs.h[:])
	hs.h = s.mixHash(hs.h[:], ciphertext)
	return ciphertext
}

func (s *secureMsg) decryptAndHash(hs *handshakeState, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) == 0 {
		hs.h = s.mixHash(hs.h[:], nil)
		return nil, nil
	}
	aead, _ := chacha20poly1305.New(hs.ck[:])
	plaintext, err := aead.Open(nil, make([]byte, 12), ciphertext, hs.h[:])
	if err != nil {
		return nil, err
	}
	hs.h = s.mixHash(hs.h[:], ciphertext)
	return plaintext, nil
}

func (s *secureMsg) HandleNoiseInit(buf []byte) ([]byte, error) {
	var init NoiseHandshakeInit
	if err := proto.Unmarshal(buf, &init); err != nil {
		return nil, err
	}
	if len(init.SenderStatic) != 32 || len(init.Ephemeral) != 32 {
		return nil, errors.New("invalid key lengths")
	}

	var remotePub, remoteEph [32]byte
	copy(remotePub[:], init.SenderStatic)
	copy(remoteEph[:], init.Ephemeral)

	// Check if we know this peer
	if _, ok := s.peerPublicKey[remotePub]; !ok {
		return nil, errors.New("unknown peer")
	}

	hs := &handshakeState{}
	copy(hs.h[:], []byte(noiseConstruction))
	hs.h = s.mixHash(hs.h[:], []byte(noiseIdentifier))
	hs.h = s.mixHash(hs.h[:], s.publicKey[:])
	hs.remoteEphemeral = remoteEph

	// Process message
	hs.h = s.mixHash(hs.h[:], remoteEph[:])
	dh, _ := curve25519.X25519(s.privateKey[:], remoteEph[:])
	hs.ck, _ = s.mixKey(hs.ck[:], dh)

	dh, _ = curve25519.X25519(s.privateKey[:], remotePub[:])
	hs.ck, _ = s.mixKey(hs.ck[:], dh)

	// Decrypt and verify
	if _, err := s.decryptAndHash(hs, init.EncryptedStatic); err != nil {
		return nil, err
	}
	if _, err := s.decryptAndHash(hs, init.EncryptedTimestamp); err != nil {
		return nil, err
	}

	s.mu.Lock()
	s.handshakes[remotePub] = hs
	s.mu.Unlock()

	// Generate response
	return s.generateNoiseResponse(remotePub)
}

func (s *secureMsg) HandleNoiseResponse(buf []byte) error {
	var resp NoiseHandshakeResponse
	if err := proto.Unmarshal(buf, &resp); err != nil {
		return err
	}
	if len(resp.SenderStatic) != 32 || len(resp.Ephemeral) != 32 {
		return errors.New("invalid key lengths")
	}

	var remotePub [32]byte
	copy(remotePub[:], resp.SenderStatic)

	s.mu.Lock()
	hs, ok := s.handshakes[remotePub]
	s.mu.Unlock()
	if !ok {
		return errors.New("no pending handshake")
	}

	// Complete handshake and derive transport keys
	ck1, ck2 := noiseHKDF(hs.ck[:], nil)

	transport := &transportState{}
	transport.sendKey = ck1
	transport.recvKey = ck2

	s.mu.Lock()
	s.transports[remotePub] = transport
	delete(s.handshakes, remotePub)
	s.mu.Unlock()
	return nil
}

func (s *secureMsg) DecryptNoiseTransport(buf []byte) (*UnencryptedMessage, error) {
	var transport NoiseTransportMessage
	if err := proto.Unmarshal(buf, &transport); err != nil {
		return nil, err
	}

	// Try to decrypt with all known transport states
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, state := range s.transports {
		aead, _ := chacha20poly1305.New(state.recvKey[:])
		nonce := make([]byte, 12)
		binary.LittleEndian.PutUint64(nonce[4:], uint64(transport.Counter))

		plaintext, err := aead.Open(nil, nonce, transport.EncryptedData, nil)
		if err != nil {
			continue // Try next peer
		}

		// Update receive counter if decryption succeeded
		if uint64(transport.Counter) >= state.recvNonce {
			state.recvNonce = uint64(transport.Counter) + 1
		}

		// Unmarshal the decrypted message
		var msg UnencryptedMessage
		if err := proto.Unmarshal(plaintext, &msg); err != nil {
			continue
		}
		return &msg, nil
	}

	return nil, errors.New("failed to decrypt transport message")
}

func (s *secureMsg) EncryptNoiseTransport(msg *UnencryptedMessage, peerPublicKey [32]byte) ([]byte, error) {
	s.mu.RLock()
	transport, ok := s.transports[peerPublicKey]
	s.mu.RUnlock()

	if !ok {
		return nil, errors.New("no established transport with peer")
	}

	// Marshal the inner message
	plaintext, err := proto.Marshal(msg)
	if err != nil {
		return nil, err
	}

	aead, _ := chacha20poly1305.New(transport.sendKey[:])
	nonce := make([]byte, 12)
	binary.LittleEndian.PutUint64(nonce[4:], transport.sendNonce)
	ciphertext := aead.Seal(nil, nonce, plaintext, nil)
	transport.sendNonce++

	noiseTransport := &NoiseTransportMessage{
		Counter:       uint32(transport.sendNonce - 1),
		EncryptedData: ciphertext,
	}

	return proto.Marshal(noiseTransport)
}

func (s *secureMsg) generateNoiseResponse(peerKey [32]byte) ([]byte, error) {
	s.mu.RLock()
	hs, ok := s.handshakes[peerKey]
	s.mu.RUnlock()
	if !ok {
		return nil, errors.New("no pending handshake")
	}

	// Generate ephemeral key
	var localEphemeral, ephPub [32]byte
	if _, err := rand.Read(localEphemeral[:]); err != nil {
		return nil, err
	}
	curve25519.ScalarBaseMult(&ephPub, &localEphemeral)

	// Continue noise handshake
	hs.h = s.mixHash(hs.h[:], ephPub[:])
	
	dh, _ := curve25519.X25519(localEphemeral[:], hs.remoteEphemeral[:])
	hs.ck, _ = s.mixKey(hs.ck[:], dh)
	
	dh, _ = curve25519.X25519(s.privateKey[:], hs.remoteEphemeral[:])
	hs.ck, _ = s.mixKey(hs.ck[:], dh)

	// Encrypt empty payload
	encNothing := s.encryptAndHash(hs, nil)

	// Complete handshake and derive transport keys
	ck1, ck2 := noiseHKDF(hs.ck[:], nil)
	transport := &transportState{
		sendKey: ck1,
		recvKey: ck2,
	}

	s.mu.Lock()
	s.transports[peerKey] = transport
	delete(s.handshakes, peerKey)
	s.mu.Unlock()

	// Build response
	response := &NoiseHandshakeResponse{
		SenderStatic:     s.publicKey[:],
		Ephemeral:        ephPub[:],
		EncryptedNothing: encNothing,
	}

	return proto.Marshal(response)
}

// SetPrivateKey implements SecureMsg
func (s *secureMsg) SetPrivateKey(key wgdevice.NoisePrivateKey) {
	copy(s.privateKey[:], key[:])
	curve25519.ScalarBaseMult(&s.publicKey, &s.privateKey)
}

// AddPeerPublicKey implements SecureMsg
func (s *secureMsg) AddPeerPublicKey(key wgdevice.NoisePublicKey) {
	var k [32]byte
	copy(k[:], key[:])
	s.peerPublicKey[k] = struct{}{}
}

func (s *secureMsg) InitiateHandshake(peerPublicKey [32]byte) ([]byte, error) {
	hs := &handshakeState{}
	copy(hs.h[:], []byte(noiseConstruction))
	hs.h = s.mixHash(hs.h[:], []byte(noiseIdentifier))
	hs.h = s.mixHash(hs.h[:], s.publicKey[:])

	// Generate ephemeral key
	if _, err := rand.Read(hs.localEphemeral[:]); err != nil {
		return nil, err
	}
	var ephPub [32]byte
	curve25519.ScalarBaseMult(&ephPub, &hs.localEphemeral)

	hs.h = s.mixHash(hs.h[:], ephPub[:])

	// DH operations
	dh, _ := curve25519.X25519(hs.localEphemeral[:], peerPublicKey[:])
	hs.ck, _ = s.mixKey(hs.ck[:], dh)

	dh, _ = curve25519.X25519(s.privateKey[:], peerPublicKey[:])
	hs.ck, _ = s.mixKey(hs.ck[:], dh)

	// Encrypt static key and timestamp
	encStatic := s.encryptAndHash(hs, s.publicKey[:])
	timestamp := make([]byte, 12)
	binary.LittleEndian.PutUint64(timestamp[4:], uint64(time.Now().Unix()))
	encTimestamp := s.encryptAndHash(hs, timestamp)

	s.mu.Lock()
	s.handshakes[peerPublicKey] = hs
	s.mu.Unlock()

	noiseInit := &NoiseHandshakeInit{
		SenderStatic:       s.publicKey[:],
		Ephemeral:          ephPub[:],
		EncryptedStatic:    encStatic,
		EncryptedTimestamp: encTimestamp,
	}

	return proto.Marshal(noiseInit)
}
