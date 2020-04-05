package certificateservice

import (
	"context"
	"crypto/x509"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	"github.com/IPA-CyberLab/kmgm/action"
	"github.com/IPA-CyberLab/kmgm/action/issue"
	"github.com/IPA-CyberLab/kmgm/dname"
	"github.com/IPA-CyberLab/kmgm/validityperiod"
	"github.com/IPA-CyberLab/kmgm/keyusage"
	"github.com/IPA-CyberLab/kmgm/pb"
	"github.com/IPA-CyberLab/kmgm/remote/user"
	"github.com/IPA-CyberLab/kmgm/san"
)

type Service struct {
	env *action.Environment
}

var _ = pb.CertificateServiceServer(&Service{})

func New(env *action.Environment) (*Service, error) {
	return &Service{env: env}, nil
}

func (svc *Service) IssueCertificate(ctx context.Context, req *pb.IssueCertificateRequest) (*pb.IssueCertificateResponse, error) {
	// FIXME[P1]: log while issue -> rely on grpc middleware logging?
	u := user.FromContext(ctx)
	if !u.IsAllowedToIssueCertificate(req.Profile) {
		return nil, grpc.Errorf(codes.Unauthenticated, "%v is not allowed to issue certificate.", u)
	}

	pub, err := x509.ParsePKIXPublicKey(req.PublicKey)
	if err != nil {
		return nil, grpc.Errorf(codes.InvalidArgument, "Failed to parse PublicKey.")
	}

	ns, err := san.FromProtoStruct(req.Names)
	if err != nil {
		return nil, grpc.Errorf(codes.InvalidArgument, "Failed to parse Names.")
	}

	cfg := &issue.Config{
		Subject:  dname.FromProtoStruct(req.Subject),
		Names:    ns,
		KeyUsage: keyusage.FromProtoStruct(req.KeyUsage),
		Validity: validityperiod.ValidityPeriod{
			NotAfter: time.Unix(req.NotAfterUnixtime, 0).UTC(),
		},
	}
	envP := svc.env.Clone()
	envP.ProfileName = req.Profile
	certDer, err := issue.Run(envP, pub, cfg)
	if err != nil {
		return nil, grpc.Errorf(codes.Internal, "%v", err)
	}

	return &pb.IssueCertificateResponse{
		Certificate: certDer,
	}, nil
}
