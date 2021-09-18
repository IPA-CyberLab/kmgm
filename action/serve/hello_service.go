package serve

import (
	"context"

	"github.com/IPA-CyberLab/kmgm/pb"
	"github.com/IPA-CyberLab/kmgm/remote/user"
)

type helloService struct {
	pb.UnimplementedHelloServiceServer
}

var _ = pb.HelloServiceServer(&helloService{})

func (helloService) Hello(ctx context.Context, req *pb.HelloRequest) (*pb.HelloResponse, error) {
	u := user.FromContext(ctx)
	return &pb.HelloResponse{
		ApiVersion:         pb.ApiVersion,
		AuthenticationType: u.Type,
		AuthenticatedUser:  u.Name,
	}, nil
}
