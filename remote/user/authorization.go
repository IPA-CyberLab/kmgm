package user

import (
	"github.com/IPA-CyberLab/kmgm/consts"
	"github.com/IPA-CyberLab/kmgm/pb"
)

// FIXME: cover other internal profiles too. For instance, reserve `kmgm serve` CA profile.

func (u User) IsAllowedToSetupCA(profileName string) bool {
	if profileName == consts.AuthProfileName {
		return false
	}
	return u.Type == pb.AuthenticationType_CLIENT_CERT
}

func (u User) IsAllowedToIssueCertificate(profileName string) bool {
	if profileName == consts.AuthProfileName &&
		u.Type == pb.AuthenticationType_BOOTSTRAP_TOKEN {
		return true
	}
	return u.Type == pb.AuthenticationType_CLIENT_CERT
}

func (u User) IsAllowedToGetCertificate() bool {
	return u.Type == pb.AuthenticationType_CLIENT_CERT
}
