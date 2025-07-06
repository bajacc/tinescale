package device

import (
	"context"
	"sync"

	pb "github.com/bajacc/tinescale/pkg/proto"
)

type PeerInfo struct {
	Candidates []string
}

type Server struct {
	pb.UnimplementedDeviceServiceServer
	mu    sync.RWMutex
	peers map[string]PeerInfo // ip => info
}

func (s *Server) LookupEndpoint(ctx context.Context, req *pb.LookupRequest) (*pb.LookupResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	peer, ok := s.peers[req.Ip]
	if !ok {
		// Default: relay if not known
		return &pb.LookupResponse{
			Candidates: []string{},
		}, nil
	}

	return &pb.LookupResponse{
		Candidates: peer.Candidates,
	}, nil
}
