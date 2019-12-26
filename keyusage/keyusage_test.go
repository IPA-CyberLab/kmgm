package keyusage_test

import (
	"testing"

	"github.com/IPA-CyberLab/kmgm/keyusage"
)

func TestKeyUsage_Equals(t *testing.T) {
	if keyusage.KeyUsageCA.Equals(keyusage.KeyUsageTLSServer) {
		t.Errorf("Unexpected: CA == TlsServer")
	}
	if keyusage.KeyUsageTLSClientServer.Equals(keyusage.KeyUsageTLSServer) {
		t.Errorf("Unexpected: cs == s")
	}
	if keyusage.KeyUsageTLSClient.Equals(keyusage.KeyUsageTLSServer) {
		t.Errorf("Unexpected: c == s")
	}
	if !keyusage.KeyUsageCA.Equals(keyusage.KeyUsageCA) {
		t.Errorf("Unexpected: CA != CA")
	}
	if !keyusage.KeyUsageTLSClientServer.Equals(keyusage.KeyUsageTLSClientServer) {
		t.Errorf("Unexpected: cs != cs")
	}
}
