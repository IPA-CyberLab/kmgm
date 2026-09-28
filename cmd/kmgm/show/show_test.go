package show_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/IPA-CyberLab/kmgm/cmd/kmgm/show"
)

func TestPrintCertInfo_KeyUsage(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		UnknownExtKeyUsage: []asn1.ObjectIdentifier{
			{1, 2, 3, 4},
		},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	show.PrintCertInfo(&buf, cert, show.FormatFull)
	out := buf.String()

	for _, expected := range []string{
		"KeyUsage (marked critical: true):\n+ digitalSignature\n+ keyEncipherment\n",
		"ExtKeyUsage (marked critical: false):\n+ serverAuth\n+ clientAuth\n+ 1.2.3.4\n",
	} {
		if !strings.Contains(out, expected) {
			t.Errorf("expected output to contain %q, got:\n%s", expected, out)
		}
	}
	if strings.Contains(out, "FIXME") {
		t.Errorf("unexpected FIXME placeholder in output:\n%s", out)
	}
}
