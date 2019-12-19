package user

import (
	"fmt"

	"github.com/IPA-CyberLab/kmgm/pb"
)

// User contains the information of an authenticated user to kmgm HTTPS/gRPC server.
type User struct {
	Type pb.AuthenticationType
	Name string
}

var Anonymous = User{
	Type: pb.AuthenticationType_ANONYMOUS,
	Name: "anonymous",
}

var BootstrapToken = User{
	Type: pb.AuthenticationType_BOOTSTRAP_TOKEN,
	Name: "bootstrapToken",
}

func ClientCert(commonName string) User {
	return User{
		Type: pb.AuthenticationType_CLIENT_CERT,
		Name: fmt.Sprintf("clientcert:%s", commonName),
	}
}

func (u User) String() string {
	return fmt.Sprintf("User[%s]", u.Name)
}
