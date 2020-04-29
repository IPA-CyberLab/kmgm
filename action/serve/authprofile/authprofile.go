package authprofile

import (
	"fmt"
	"time"

	"github.com/IPA-CyberLab/kmgm/action"
	"github.com/IPA-CyberLab/kmgm/action/setup"
	"github.com/IPA-CyberLab/kmgm/consts"
	"github.com/IPA-CyberLab/kmgm/dname"
	"github.com/IPA-CyberLab/kmgm/storage"
	"github.com/IPA-CyberLab/kmgm/wcrypto"
)

// The name of internal storage profile to serve as kmgm HTTPS/gRPC server client auth.
const ProfileName = consts.AuthProfileName

func Ensure(env *action.Environment) (*storage.Profile, error) {
	slog := env.Logger.Sugar()

	profile, err := env.Storage.Profile(ProfileName)
	if err != nil {
		return nil, err
	}

	st := profile.Status(env.NowImpl())
	switch st.Code {
	case storage.ValidCA:
		return profile, nil
	case storage.NotCA:
		slog.Infof("Setting up CA for kmgm HTTPS/gRPC server.")
		start := time.Now()
		defer func() {
			slog.Infow("Setting up CA for kmgm HTTPS/gRPC server... Done.", "took", time.Now().Sub(start))
		}()

		// Create CA
		envS := env.Clone()
		envS.ProfileName = ProfileName

		cfg := setup.DefaultConfig(nil)
		cfg.Subject = &dname.Config{
			CommonName: "kmgm serverauth CA",
		}
		cfg.KeyType = wcrypto.ServerKeyType

		if err := setup.Run(envS, cfg); err != nil {
			return nil, fmt.Errorf("Failed to setup serverauth CA: %v", err)
		}

		if st := profile.Status(env.NowImpl()); st.Code != storage.ValidCA {
			return nil, st
		}
		return profile, nil
	default:
		return nil, st
	}
}
