//go:generate protoc --go_out=paths=source_relative:. securemsg.proto
package securemsg

import (
	wgdevice "golang.zx2c4.com/wireguard/device"
	"google.golang.org/protobuf/proto"
)

type SecureMsg interface {
	Process(bufs [][]byte)
	OnSendPongMessage(send func(bufs [][]byte) error)
	OnSendFromRelayMessage(send func(bufs [][]byte) error)
}

type secureMsg struct {
	log                  *wgdevice.Logger
	privateKey           wgdevice.NoisePrivateKey
	peerPublicKey        map[wgdevice.NoisePublicKey]struct{}
	sendPongMessage      func(bufs [][]byte) error
	sendFromRelayMessage func(bufs [][]byte) error
}

func New() SecureMsg {
	return &secureMsg{}
}

// OnSendFromRelayMessage implements SecureMsg.
func (s *secureMsg) OnSendFromRelayMessage(send func(bufs [][]byte) error) {
	s.sendFromRelayMessage = send
}

// OnSendPongMessage implements SecureMsg.
func (s *secureMsg) OnSendPongMessage(send func(bufs [][]byte) error) {
	s.sendPongMessage = send
}

func (s *secureMsg) decrypt(buf []byte) ([]byte, error) {
	// Decrypt the message using the appropriate decryption method.
	// This is a placeholder for actual decryption logic.
	// For example, you might use a symmetric key decryption here.
	return buf, nil // Replace with actual decryption logic
}

func (s *secureMsg) encrypt(buf []byte) ([]byte, error) {
	// Encrypt the message using the appropriate encryption method.
	// This is a placeholder for actual encryption logic.
	// For example, you might use a symmetric key encryption here.
	return buf, nil // Replace with actual encryption logic
}

// Process implements SecureMsg.
func (s *secureMsg) Process(bufs [][]byte) {
	relayMessages := make([][]byte, 0, len(bufs))
	PongMessages := make([][]byte, 0, len(bufs))
	for _, buf := range bufs {
		plainText, err := s.decrypt(buf)
		if err != nil {
			s.log.Errorf("failed to decrypt secure message: %v", err)
			continue
		}
		var wrapper MessageWrapper
		if err := proto.Unmarshal(plainText, &wrapper); err != nil {
			s.log.Errorf("failed to unmarshal secure message: %v", err)
			continue
		}

		s.processDecrypted(&wrapper)

	}
	s.sendFromRelayMessage(relayMessages)
	s.sendPongMessage(PongMessages)
}

func (s *secureMsg) processDecrypted(msg *MessageWrapper) {
	switch m := msg.MessageType.(type) {
	case *MessageWrapper_EndpointResponse:
		s.log.Debugf("Received EndpointResponse: %v", m.EndpointResponse)
	case *MessageWrapper_ToRelay:
		s.log.Debugf("Received ToRelayMessage: %v", m.ToRelay)
	case *MessageWrapper_FromRelay:
		s.log.Debugf("Received FromRelayMessage: %v", m.FromRelay)
	case *MessageWrapper_PingMessage:
		s.log.Debugf("Received PingMessage: %v", m.PingMessage)
	case *MessageWrapper_PongMessage:
		s.log.Debugf("Received PongMessage: %v", m.PongMessage)
	default:
		s.log.Errorf("Unknown message type received")
	}
}
