package user

import (
	"github.com/IPA-CyberLab/kmgm/consts"
	"github.com/IPA-CyberLab/kmgm/pb"
)

func (u User) IsAllowedToIssueCertificate(profileName string) bool {
	if profileName == consts.AuthProfileName &&
		u.Type == pb.AuthenticationType_BOOTSTRAP_TOKEN {
		return true
	}
	return u.Type == pb.AuthenticationType_CLIENT_CERT
}
