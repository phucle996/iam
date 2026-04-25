package grpc

import (
	"context"
	"strings"
	"time"

	"iam/internal/security"
	"iam/internal/transport/grpc/secretpb"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type secretRuntimeServer struct {
	secretpb.UnimplementedSecretRuntimeServiceServer
	provider security.SecretProvider
}

func RegisterSecretRuntimeService(server grpc.ServiceRegistrar, provider security.SecretProvider) {
	if server == nil || provider == nil {
		return
	}
	secretpb.RegisterSecretRuntimeServiceServer(server, &secretRuntimeServer{provider: provider})
}

func (s *secretRuntimeServer) GetSecretCandidates(ctx context.Context, req *secretpb.GetSecretCandidatesRequest) (*secretpb.GetSecretCandidatesResponse, error) {
	if s == nil || s.provider == nil {
		return nil, status.Error(codes.Unavailable, "secret provider unavailable")
	}

	families := normalizeFamilies(req.GetFamilies())
	if len(families) == 0 {
		return nil, status.Error(codes.InvalidArgument, "secret family is required")
	}

	response := &secretpb.GetSecretCandidatesResponse{Families: make(map[string]*secretpb.SecretVersionList, len(families))}
	for _, family := range families {
		candidates, err := s.provider.GetCandidates(family)
		if err != nil {
			return nil, status.Error(codes.Unavailable, "secret candidates unavailable")
		}

		items := make([]*secretpb.SecretVersion, 0, len(candidates))
		for _, candidate := range candidates {
			if strings.TrimSpace(candidate.Value) == "" {
				continue
			}
			items = append(items, &secretpb.SecretVersion{
				Family:    candidate.Family,
				Version:   candidate.Version,
				Value:     candidate.Value,
				ExpiresAt: timestampOrNil(candidate.ExpiresAt),
				RotatedAt: timestampOrNil(candidate.RotatedAt),
			})
		}
		if len(items) == 0 {
			return nil, status.Error(codes.Unavailable, "secret candidates unavailable")
		}
		response.Families[family] = &secretpb.SecretVersionList{Candidates: items}
	}

	return response, nil
}

func normalizeFamilies(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func timestampOrNil(value time.Time) *timestamppb.Timestamp {
	if value.IsZero() {
		return nil
	}
	return timestamppb.New(value)
}
