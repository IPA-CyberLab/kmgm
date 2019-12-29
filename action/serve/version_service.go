package serve

import (
	"context"

	"github.com/IPA-CyberLab/kmgm/pb"
	"github.com/IPA-CyberLab/kmgm/version"
)

type versionService struct{}

var _ = pb.VersionServiceServer(&versionService{})

func (versionService) GetVersion(ctx context.Context, req *pb.GetVersionRequest) (*pb.GetVersionResponse, error) {
	return &pb.GetVersionResponse{
		Version: version.Version,
		Commit:  version.Commit,
	}, nil
}
