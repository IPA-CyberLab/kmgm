package hello

import (
	"context"
	"fmt"

	"go.uber.org/zap"
	"google.golang.org/grpc"

	"github.com/IPA-CyberLab/kmgm/pb"
	"github.com/IPA-CyberLab/kmgm/remote/user"
)

func Hello(ctx context.Context, conn *grpc.ClientConn, l *zap.Logger) (user.User, error) {
	slog := l.Sugar()

	sc := pb.NewHelloServiceClient(conn)
	resp, err := sc.Hello(ctx, &pb.HelloRequest{})
	if err != nil {
		return user.User{}, err
	}

	if resp.ApiVersion != pb.ApiVersion {
		err := fmt.Errorf(
			"Server version %d and client version %d mismatch.",
			resp.ApiVersion, pb.ApiVersion)
		return user.User{}, err
	}

	slog.Debugf("Server recognizes me as the user %q", resp.AuthenticatedUser)
	au := user.User{
		Type: resp.AuthenticationType,
		Name: resp.AuthenticatedUser,
	}
	return au, nil
}
