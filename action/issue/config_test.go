package issue_test

import (
	"testing"

	"github.com/IPA-CyberLab/kmgm/action/issue"
	"github.com/IPA-CyberLab/kmgm/pemparser"
	"github.com/IPA-CyberLab/kmgm/wcrypto"
)

const testCertPem = `-----BEGIN CERTIFICATE-----
MIIBmjCCAUGgAwIBAgIIYw/GUWnaxD4wCgYIKoZIzj0EAwIwEjEQMA4GA1UEAxMH
dGVzdCBDQTAeFw0xOTEyMjkxMjUxMDNaFw0yMjAzMjgxMjUyMDNaMBIxEDAOBgNV
BAMMB3Rlc3RfY24wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASJNqgEYpQNmZO9
fDPoqs84G4vl++6gJyumdRny+OX/lqLlb6VdYFmfd5S7XhCHUUp0jGulQO7WxDsn
cXLxHu9do4GAMH4wDgYDVR0PAQH/BAQDAgWgMB0GA1UdJQQWMBQGCCsGAQUFBwMC
BggrBgEFBQcDATAMBgNVHRMBAf8EAjAAMB8GA1UdIwQYMBaAFEMkkSwCNkQq7Z6N
MWGhLNpHv5z6MB4GA1UdEQQXMBWCE3Rlc3QtY24uZXhhbXBsZS5jb20wCgYIKoZI
zj0EAwIDRwAwRAIgRtlJshmnNsQKwvMYMTiF4a8XXu1aytz3cmVi8NMy4ykCIAVn
cXdZYB/A9OZlZbB1J6dhVN8z9owmfdznO7ln3Iol
-----END CERTIFICATE-----`

func TestConfigFromCert(t *testing.T) {
	certs, err := pemparser.ParseCertificates([]byte(testCertPem))
	if err != nil {
		t.Fatalf("%v", err)
	}
	if len(certs) != 1 {
		t.Fatalf("len(certs)=%d", len(certs))
	}

	cert := certs[0]
	cfg, err := issue.ConfigFromCert(cert)
	if err != nil {
		t.Fatalf("%v", err)
	}
	if cfg.KeyType != wcrypto.KeySECP256R1 {
		t.Errorf("KeyType")
	}
	// FIXME[P0] cfg.Equals(expected)
}
