package keyusage_test

import (
	"crypto/x509"
	"reflect"
	"testing"

	"github.com/IPA-CyberLab/kmgm/keyusage"
)

func TestKeyUsageNames(t *testing.T) {
	testcases := []struct {
		ku       x509.KeyUsage
		expected []string
	}{
		{0, nil},
		{keyusage.KeyUsageCA.KeyUsage, []string{"keyCertSign", "cRLSign"}},
		{keyusage.KeyUsageTLSServer.KeyUsage, []string{"digitalSignature", "keyEncipherment"}},
		{x509.KeyUsageDecipherOnly | 1<<10, []string{"decipherOnly", "unknown(bit 10)"}},
	}
	for _, tc := range testcases {
		actual := keyusage.KeyUsageNames(tc.ku)
		if !reflect.DeepEqual(actual, tc.expected) {
			t.Errorf("KeyUsageNames(%d): expected %v, got %v", tc.ku, tc.expected, actual)
		}
	}
}

func TestExtKeyUsageName(t *testing.T) {
	testcases := []struct {
		eku      x509.ExtKeyUsage
		expected string
	}{
		{x509.ExtKeyUsageAny, "any"},
		{x509.ExtKeyUsageServerAuth, "serverAuth"},
		{x509.ExtKeyUsageClientAuth, "clientAuth"},
		{x509.ExtKeyUsageOCSPSigning, "OCSPSigning"},
		{x509.ExtKeyUsage(9999), "unknown(9999)"},
	}
	for _, tc := range testcases {
		if actual := keyusage.ExtKeyUsageName(tc.eku); actual != tc.expected {
			t.Errorf("ExtKeyUsageName(%d): expected %q, got %q", tc.eku, tc.expected, actual)
		}
	}
}
