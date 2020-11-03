package pemparser_test

import (
	"encoding/asn1"
	"errors"
	"testing"

	"github.com/IPA-CyberLab/kmgm/pemparser"
)

var TestCSR = []byte(`-----BEGIN CERTIFICATE REQUEST-----
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
`)

var IncompleteCSR = []byte(`-----BEGIN CERTIFICATE REQUEST-----
MIHzMIGaAgEAMAAwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQzH2cBP3lcXHwm
451JhOmDRq1Y/ZbNgw00r5mSf5r9hqR/Xd+30QhiHOrCA7LfE0vKCNuidndDTH8Q
95VrjM8ooDgwNgYJKoZIhvcNAQkOMSkwJzAYBgNVHREEETAPgg1lY2RzYS5leGFt
cGxlMAsGA1UdDwQEAwIFoDAKBggqhkjOPQQDAgNIADBFAiEAsEvJuhNtieOyEmqN
lXabDvu2IoDqCshBpwyjsvy+rTUCIAW/Dn80lqxR2YQiMYujLxP84EOPZfwY1e7p
-----END CERTIFICATE REQUEST-----
`)

func Test_ParseCertificateRequest(t *testing.T) {
	_, err := pemparser.ParseCertificateRequest([]byte{})
	if err == nil {
		t.Errorf("Expected err for parsing empty input")
	}

	req, err := pemparser.ParseCertificateRequest(TestCSR)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if req.Subject.CommonName != "hogefuga" {
		t.Errorf("Unexpected CN: %s", req.Subject.CommonName)
	}

	multipleCSRs := append([]byte(TestCSR), []byte(TestCSR)...)
	_, err = pemparser.ParseCertificateRequest(multipleCSRs)
	if err != pemparser.ErrMultipleCertificateRequestBlocks {
		t.Errorf("Unexpected error: %v", err)
	}

	_, err = pemparser.ParseCertificateRequest(IncompleteCSR)
	var asnsynerr asn1.SyntaxError
	if !errors.As(err, &asnsynerr) {
		t.Errorf("Unexpected err when parsing incomplete csr pem: %v", err)
	}
}
