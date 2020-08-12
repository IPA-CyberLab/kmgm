package pemparser_test

import (
	"testing"

	"github.com/IPA-CyberLab/kmgm/pemparser"
)

const TestCSR = `-----BEGIN CERTIFICATE REQUEST-----
MIICmDCCAYACAQAwUzELMAkGA1UEBhMCSlAxDjAMBgNVBAgMBVRva3lvMSEwHwYD
VQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQxETAPBgNVBAMMCGhvZ2VmdWdh
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0f7/xMDop3WNJAYuWFaJ
G5dcbzXRlWk4PHAtZjxQPCKP/lN0pHGyCFs58v4rg7OFba+5WFg9DznvzYukhE7Z
rIej/E4Xpl1LUQcaSm6IdzzBUUF6+rOuufLZMV1v1eaa3KIT96u+65k9+eM7CmkK
cke2dIQs7/OTz+viq/8dFZnSRWCyH0HPE61wF79VHJgAt6Cdi4muWgcBgxg+8nRv
vy0XO70Z2EYtD01ncsoNb+Xd9v6eXLsMBWbMzljN/5rKlybodwnXgMcz2RzQdeuY
PA4MYh5dwieZ23UaKB5IX2IvieCOz5KYT8hsS54HUXQX+DBPnj4uqwVMDAG+xbK8
uwIDAQABoAAwDQYJKoZIhvcNAQELBQADggEBAJXCcsaRXvx1T+AdOvF5aFElJ9tn
00gK8gWf4uyOOypOv3XUzdmuk93m2zkuCTvdC1lyj7KogJR6oHe+Y4UhJBqISh1J
+8ZKSBlusicJftHhxR3s63Zy7cKHu57CdrLW8eYY+Wrt53s/EzN8Rv0s5kQTWtjI
2v7IFUJe81tf5NDW8f4vqcilqM4pA4IqzPJCoulXTlCMiJhhJGFP76YpDOfZX7eA
X/8dzdW3bJ6aBNkt+mMFIk32veY0NKaflVo57FauPyD6/9d1PajYXsTMXL4O/c5j
Lv7aCvdGIifcy7qV0Slxjg6YbDtai0MGogOvsxSFsSzUmwGnfDGb9Q9nhog=
-----END CERTIFICATE REQUEST-----
`

func Test_ParseCertificateRequest(t *testing.T) {
	req, err := pemparser.ParseCertificateRequest([]byte(TestCSR))
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if req.Subject.CommonName != "hogefuga" {
		t.Errorf("Unexpected CN: %s", req.Subject.CommonName)
	}

	multipleCSRs := append([]byte(TestCSR), []byte(TestCSR)...)
	req, err = pemparser.ParseCertificateRequest(multipleCSRs)
	if err != pemparser.ErrMultipleCertificateRequestBlocks {
		t.Errorf("Unexpected error: %v", err)
	}
}
