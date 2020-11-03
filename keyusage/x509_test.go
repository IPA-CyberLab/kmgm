package keyusage_test

import (
	"crypto/x509"
	"testing"

	"github.com/IPA-CyberLab/kmgm/keyusage"
	"github.com/IPA-CyberLab/kmgm/pemparser"
)

func TestFromCSR(t *testing.T) {
	testcases := []struct {
		Comment  string
		PEM      string
		Expected keyusage.KeyUsage
	}{
		{"no usage",
			/*
			   apiVersion: cert-manager.io/v1
			   kind: Certificate
			   metadata:
			     name: kmgm-test-cert
			   spec:
			     secretName: kmgm-test-cert
			     dnsNames:
			     - bar.example
			     issuerRef:
			       name: kmgm-test-issuer
			       kind: Issuer
			       group: kmgm-issuer.coe.ad.jp
			     privateKey:
			       size: 4096
			*/
			`-----BEGIN CERTIFICATE REQUEST-----
MIIEezCCAmMCAQAwADCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAMLw
yO/DJ4tl9ly8BjhSg86nAAfQX/B1YXStwLlkw1phF05VY/dyYfKQOpPsaqprQ3m7
jeCxUS0FFCPrY6d8NCu9WQBzWKBTn0RNVtOCw6PN+C1tRBQbu4nbAJO/WmhrA2T6
xPuNglBI+8Z3Bn5RnlQJeh5cxUdDRL3mURR4/5iK62d4wQF46KfAWN0BIsl2DxMt
0Ea5t4n+GC4YRu9U/ITc7PvLaip5fhmb+YeYyC+24CF55sjoYUL3+W6f6kbcjGx1
gKP4qZFJ8OiaIuqaKJRqSKmahFLbOZrY+Dq/yKXjK4DICoLzs/lWY04xhvdNTTdX
9FohVf1F2kXmk6zmCMiFUW8qZcP0igMmrgDceTycJjmsP8G7d1YP8QqWUT5/vZC9
huzz6G1qJlUyIRtFJOoC10Hd9Nf/oS6ngg1YJcqNR2Nj9/fIpk+Vbv0XeDJJ27mx
fNmmR0EzCda8R+CAtMkA9jir2vh5vv0sVZ41AeV989ruqXGHmhupScbHl6/7J+n/
M118qxUfQHZzBHZw12G2uVpSw4QWTPCppAhr9LWEhuLjGedG5hqhlaqCfjl2NQ8e
FrrhwJ/n6LuXr/+sCYanuNXUOSVtSmfyqengYmWtwrZW+CS8Jbn5KTK9Vcf8+bCR
ydotBXCj8ry/Nj/WzX2teQUpMxZATvDKq2xNm69XAgMBAAGgNjA0BgkqhkiG9w0B
CQ4xJzAlMBYGA1UdEQQPMA2CC2Jhci5leGFtcGxlMAsGA1UdDwQEAwIFoDANBgkq
hkiG9w0BAQsFAAOCAgEAO2YDXWc+/uZeRAd5CLr3PTfjGK4zEH2H+glYH15UGt2Y
G4KvhhoFd+OJlaMeF8mIIx+aouDU053lLNlD3LYppvNbkexaJFOjCH3rvrRrTKs3
1ZT8YSTdwjhc+iGW+3Pf4LdAp3+zAK7EH1PgkWm/8Ie+8uvoMEmV3JZt6vACP7LO
LT3uDWISJNkXHnzYYN5nsaqyJIGw0HNtKbShp1xWPLxcP5YBCMhvk4S4j3pt1qwC
KO+vxm4rYpOpN1Vv6sdQvjUnmPBVauxDI+Jy63F1lvXVQ8NoT9OpwgPF8nRK9Ca4
ULgC5KJkhVaNjUFHJ/O35xEpA3qzmCySsVfvTNAvoTK2uR6mCgHTn0B5Ss3k2ohI
Ne0I7zXOPo5JfVOZX8CWXBpMO/atRtzL+4A3SNRBA3jee1jIMwwD4/VXg6/4252t
UU+KaHoD7lHnQDyBhLKgvn3V/sEwCW3ZW2EKpDnIMyfF025mA3oretsjtgOKJdj6
/JF0/OrU4Sxh8C5tLUCQCfRet65t9h7VrNVN7Qz5W29GkIPdYhJlcxgdDToo7T0a
I+VZoQwXdTl4hmntl6rodGApIIjq28kX2WwJwQZfbQlWzuDDC7U+UFHe2lKHwYOd
xz0DPRAT+f4no6b7q7rp0b132YDS6OPcr84ZBQ1Ro+KRMQUkTKIc5U0Un165kbs=
-----END CERTIFICATE REQUEST-----`,
			keyusage.KeyUsage{
				KeyUsage: x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
			},
		},
		{"custom usage",
			/*
			   apiVersion: cert-manager.io/v1
			   kind: Certificate
			   metadata:
			     name: kmgm-test-cert3
			   spec:
			     secretName: kmgm-test-cert3
			     dnsNames:
			     - example.foobar
			     issuerRef:
			       name: kmgm-test-issuer
			       kind: Issuer
			       group: kmgm-issuer.coe.ad.jp
			     privateKey:
			       size: 4096
			     usages:
			     - "digital signature"
			     - "key encipherment"
			     - "client auth"
			*/
			`-----BEGIN CERTIFICATE REQUEST-----
MIIEkzCCAnsCAQAwADCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALJK
/XrJTK0/b5lN5Mr3fFJDa6yZR2nLQA5831MP0knOySL0WIfNljHamBnnSgOTsDxG
iyRabwfgFZ4uSMeZCrcSHfk3+VcseZSbxXdFZjF8bDyY3zTTSNDce4ZiAX83hwhA
Qh1X9CzHkBta7k2PN5fAhpLR1a/xtCp6b64GHXJKWR6AnMQfrwV64JCEcx6LS15x
MrvmeM+kgfi0j0EYfgpIyYVJ22tmNlUJhlaEaM9KcmPPTY8aZw54oiNRSWeDPfl+
ZFiXIekwib+3qaAngCy7r8+/8gpNmzwT+CZlyx/61jiKDqdwEJAD7Ce8bKP5IQJL
LK91FycHgOGEPs3v6DjfkvI7hmyuhdhKihCK24ovBNcJDgYP/FZPUNkF5plHxUUx
bKFV7nSsom8jbCYuGYaxWkf3fjViFoktrgbhKlG0z5sJrUu622FwUWm4oL3o0CqA
qq9NMMIJmjJSTaxlooWFEqdBTwaKP3lLHQGd4oXwrMQdrNfyQdRx+txQV9/viQ+V
ldARjEu2+0F00IawpFhRvy45WOfk2LKSwsU1+U5EiAbdJE7/4/UH4KxASAQ5QMCW
f8DTboqdt6V/AI5Zt3Zo3BS42ca5Khtm+bg70370xGzKYS3slqmC7cf4bJubTyD5
qO7/rBdkE8SgmY3qdHKxRNzPrpmAdslWJyuTvKT9AgMBAAGgTjBMBgkqhkiG9w0B
CQ4xPzA9MBkGA1UdEQQSMBCCDmV4YW1wbGUuZm9vYmFyMAsGA1UdDwQEAwIFoDAT
BgNVHSUEDDAKBggrBgEFBQcDAjANBgkqhkiG9w0BAQsFAAOCAgEAJusoZEMMPmOT
UDjhRcEwvRYNrsCudZwIJ5Bhv+2evBsZ0MS2pOHN8heQ/acT9H7U+8RLavqz9zw5
uE0b3EkrLGtWGRMwqXwL0Ls4usUaO6HE7BaHcchIzSCI5ShmJ8QznMdOftmcOfwB
Vqydt2zarlrh8Pj8VyKC6lC5iijfrWNUVCKBFQu9mPZJRdkIYNU0ksyJ/zCAWknE
C/8KFZUr9m4k0+k8dgEkSINong0ianWvzwwMHwRVbzxd74PUHh2jXNFocBNfBSbD
Iu1173BX7bospFmq2Ap3fn3T42HdMU/kDim2b+6AdLfgmNpml2em3gmZIBjzrSks
/Y9jV+KZLdoacKdLsDnpVmlXBr86zVezoR9PbFlsrdvhT5YKOBG7vFwTYRbmWhZ0
ei9tTx44weltYRV6wrNhcNP7Wus5jGsDLMHXGY9bg6yoOls5uBUgaUVFzcfrstVX
aTQ032yfKu2GhofzHMv2I059sOF/yQxGZ46bRpOow06zJLPOFz0rhs4zIk5J+KN9
+kxv1HrA3kaFuWPNlItmiduDUcQrt/ceQDWE2Y7U/hU1h49IQxg1VFUp2+xVI825
Ko8pTMssA+JTdIMFErzAvhd6vKAE/KEBJW8AugfbFI2AGI0h92NtmVV5NCh5vKwR
Gq3o+TTUlnWc7zEPT12zxGYXUf1SP4g=
-----END CERTIFICATE REQUEST-----`,
			keyusage.KeyUsageTLSClient,
		},
	}

	for _, tc := range testcases {
		req, err := pemparser.ParseCertificateRequest([]byte(tc.PEM))
		if err != nil {
			t.Fatalf("%q Failed to parse test case creq: %v", tc.Comment, err)
		}

		ku, err := keyusage.FromCSR(req)
		if err != nil {
			t.Errorf("%q Unexpected KeyUsageFromCSR error: %v", tc.Comment, err)
		}

		if !ku.Equals(tc.Expected) {
			t.Errorf("%q expected: %v, actual: %v", tc.Comment, tc.Expected, ku)
		}
	}
}
