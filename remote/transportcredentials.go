package remote

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"

	"github.com/IPA-CyberLab/kmgm/wcrypto"
	"google.golang.org/grpc/credentials"
)

// TransportCredentials is grpc.tlsCreds + pubkey pinning support.
type TransportCredentials struct {
	tlscreds     credentials.TransportCredentials
	PinnedPubKey string
	PeerPubKeys  map[string]struct{}
}

var _ = credentials.TransportCredentials(&TransportCredentials{})

func NewTransportCredentials(c *tls.Config, pinnedpubkey string) *TransportCredentials {
	return &TransportCredentials{
		tlscreds:     credentials.NewTLS(c),
		PinnedPubKey: pinnedpubkey,
		PeerPubKeys:  make(map[string]struct{}),
	}
}

func (c *TransportCredentials) Info() credentials.ProtocolInfo {
	return c.tlscreds.Info()
}

func (c *TransportCredentials) ClientHandshake(ctx context.Context, authority string, rawConn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	conn, authinfo, err := c.tlscreds.ClientHandshake(ctx, authority, rawConn)
	if err != nil {
		return nil, nil, err
	}

	ti := authinfo.(credentials.TLSInfo)

	found := false

	pcerts := ti.State.PeerCertificates
	for _, pcert := range pcerts {
		pubkeyhash, err := wcrypto.PubKeyPinString(pcert.PublicKey)
		if err != nil {
			// FIXME[P2]: how should we handle this? at least log?
			continue
		}

		c.PeerPubKeys[pubkeyhash] = struct{}{}

		if pubkeyhash == c.PinnedPubKey {
			found = true
			break
		}
	}

	if c.PinnedPubKey != "" && !found {
		_ = conn.Close()

		return nil, nil, fmt.Errorf("Server certificate did not match pinnedpubkey %q.", c.PinnedPubKey)
	}

	return conn, authinfo, nil
}

func (c *TransportCredentials) ServerHandshake(rawConn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	return nil, nil, errors.New("Not implemented.")
}

func (c *TransportCredentials) Clone() credentials.TransportCredentials {
	return &TransportCredentials{
		tlscreds:     c.tlscreds.Clone(),
		PinnedPubKey: c.PinnedPubKey,
	}
}

func (c *TransportCredentials) OverrideServerName(serverNameOverride string) error {
	return c.tlscreds.OverrideServerName(serverNameOverride)
}
