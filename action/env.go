package action

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"time"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"gopkg.in/yaml.v2"

	"github.com/IPA-CyberLab/kmgm/frontend"
	"github.com/IPA-CyberLab/kmgm/remote"
	"github.com/IPA-CyberLab/kmgm/remote/hello"
	"github.com/IPA-CyberLab/kmgm/storage"
)

type Environment struct {
	Storage  *storage.Storage
	Randr    io.Reader
	Frontend frontend.Frontend
	Logger   *zap.Logger
	NowImpl  func() time.Time

	ProfileName string

	ConnectionInfo remote.ConnectionInfo
	ClientConn     *grpc.ClientConn
}

func NewEnvironment(fe frontend.Frontend, stor *storage.Storage) (*Environment, error) {
	l := zap.L()

	cfg := &Environment{
		Storage:  stor,
		Randr:    rand.Reader,
		Frontend: fe,
		Logger:   l,
		NowImpl:  time.Now,

		ProfileName: storage.DefaultProfileName,
	}
	return cfg, nil
}

func (env *Environment) Clone() *Environment {
	return &Environment{
		Storage:  env.Storage,
		Randr:    env.Randr,
		Frontend: env.Frontend,
		Logger:   env.Logger,
		NowImpl:  env.NowImpl,

		ProfileName: env.ProfileName,

		ConnectionInfo: env.ConnectionInfo,
		ClientConn:     nil, // Don't clone
	}
}

func (env *Environment) SaveConnectionInfo() error {
	path := env.Storage.ConnectionInfoPath()

	bs, err := yaml.Marshal(env.ConnectionInfo)
	if err != nil {
		return fmt.Errorf("Failed to marshal ConnectionInfo to yaml: %w", err)
	}

	if err := ioutil.WriteFile(path, bs, 0644); err != nil {
		return fmt.Errorf("Failed to write server connection info to %q: %w", path, err)
	}
	env.Logger.Sugar().Infof("Wrote server connection info to file %q.", path)

	return nil
}

func (env *Environment) LoadConnectionInfo() error {
	slog := env.Logger.Sugar()
	path := env.Storage.ConnectionInfoPath()

	bs, err := ioutil.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			slog.Warnf("Could not find server connection info file %q. Ignoring.", path)
			return nil
		}
		return err
	}

	if err := yaml.Unmarshal(bs, &env.ConnectionInfo); err != nil {
		return fmt.Errorf("Failed to unmarshal server connection info: %w", err)
	}

	return nil
}

func (env *Environment) EnsureClientConn(ctx context.Context) error {
	if env.ClientConn != nil {
		return nil
	}

	conn, err := env.ConnectionInfo.Dial(ctx, env.Logger)
	if err != nil {
		return err
	}
	if hello.Hello(ctx, conn, env.Logger); err != nil {
		return err
	}

	env.ClientConn = conn
	return nil
}

func (env *Environment) Profile() (*storage.Profile, error) {
	return env.Storage.Profile(env.ProfileName)
}

var GlobalEnvironment *Environment
