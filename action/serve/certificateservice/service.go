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
	"github.com/IPA-CyberLab/kmgm/keyusage"
	"github.com/IPA-CyberLab/kmgm/pb"
	"github.com/IPA-CyberLab/kmgm/pemparser"
	"github.com/IPA-CyberLab/kmgm/period"
	"github.com/IPA-CyberLab/kmgm/remote/user"
	"github.com/IPA-CyberLab/kmgm/san"
	"github.com/IPA-CyberLab/kmgm/storage"
	"github.com/IPA-CyberLab/kmgm/storage/issuedb"
)

type Service struct {
	env *action.Environment
}

var _ = pb.CertificateServiceServer(&Service{})

func New(env *action.Environment) (*Service, error) {
	return &Service{env: env}, nil
}

func (svc *Service) IssuePreflight(ctx context.Context, req *pb.IssuePreflightRequest) (*pb.IssuePreflightResponse, error) {
	slog := svc.env.Logger.Sugar()

	u := user.FromContext(ctx)
	if !u.IsAllowedToIssueCertificate(req.Profile) {
		return nil, grpc.Errorf(codes.Unauthenticated, "%v is not allowed to issue certificate.", u)
	}

	if err := storage.VerifyProfileName(req.Profile); err != nil {
		return nil, grpc.Errorf(codes.InvalidArgument, "%v", err)
	}

	profile, err := svc.env.Storage.Profile(req.Profile)
	if err != nil {
		slog.Infof("IssuePreflight: Storage.Profile(%q) returned err: %v", req.Profile, err)
		return nil, grpc.Errorf(codes.NotFound, "Failed to access specified profile.")
	}
	if st := profile.Status(time.Now()); st.Code != storage.ValidCA {
		return nil, grpc.Errorf(codes.Internal, "Can't issue certificate from CA profile %q: %v", req.Profile, st)
	}

	return &pb.IssuePreflightResponse{}, nil
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
		Validity: period.ValidityPeriod{
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

func (svc *Service) GetCertificate(ctx context.Context, req *pb.GetCertificateRequest) (*pb.GetCertificateResponse, error) {
	u := user.FromContext(ctx)
	if !u.IsAllowedToGetCertificate() {
		return nil, grpc.Errorf(codes.Unauthenticated, "%v is not allowed to get certificate.", u)
	}
	env := svc.env

	profile, err := env.Storage.Profile(req.Profile)
	if err != nil {
		return nil, grpc.Errorf(codes.Internal, "%v", err)
	}

	if req.SerialNumber == 0 {
		cacert, err := profile.ReadCACertificate()
		if err != nil {
			return nil, grpc.Errorf(codes.Internal, "%v", err)
		}

		return &pb.GetCertificateResponse{Certificate: cacert.Raw}, nil
	}

	db, err := issuedb.New(profile.IssueDBPath())
	if err != nil {
		return nil, grpc.Errorf(codes.Internal, "%v", err)
	}

	e, err := db.Query(req.SerialNumber)
	if err != nil {
		return nil, grpc.Errorf(codes.Internal, "%v", err)
	}

	cs, err := pemparser.ParseCertificates([]byte(e.CertificatePEM))
	if err != nil {
		return nil, grpc.Errorf(codes.Internal, "%v", err)
	}
	if len(cs) != 1 {
		return nil, grpc.Errorf(codes.Internal, "multiple certificates unexpected: %v", err)
	}
	c := cs[0]

	return &pb.GetCertificateResponse{Certificate: c.Raw}, nil
}
