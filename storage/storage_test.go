package storage_test

import (
	"fmt"
	"testing"

	"github.com/IPA-CyberLab/kmgm/storage"
)

func TestVerifyProfileName(t *testing.T) {
	testcases := []struct {
		Name  string
		Valid bool
	}{
		{"default", true},
		{"foobar", true},
		{"a", true},
		{"a_b_c", true},
		{"a-b-c", true},
		{".kmgm_server", true},
		{"", false},
		{".", false},
		{"..", false},
		{"./..", false},
		{"日本語", false},
	}

	for _, tc := range testcases {
		err := storage.VerifyProfileName(tc.Name)
		if tc.Valid {
			if err != nil {
				t.Errorf("%q expected to be a valid profile name, got %v", tc.Name, err)
			}
		} else {
			if err == nil {
				t.Errorf("%q expected to be a invalid profile name, got valid", tc.Name)
			}
		}
	}
}

const TestCertPem = `-----BEGIN CERTIFICATE-----
MIIE7jCCAtagAwIBAgIBATANBgkqhkiG9w0BAQsFADAXMRUwEwYDVQQDEwx3Y3J5
cHRvIHRlc3QwHhcNMTkxMDE3MTMxMDUxWhcNMjkxMDE0MTMxMTUxWjAXMRUwEwYD
VQQDEwx3Y3J5cHRvIHRlc3QwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoIC
AQDkVilip3w0ITSUEDsz3KpEgphf8cmCRei9hBScX+kdHVScrlPUMbT0ER+Kh37n
xKumANt2UKapX8OpFC+NTufmD4qxXJ5G9y9imG0adGe09BD3TXPf8BWV+HCkrLUb
il6s2simMkZ4KY/ddTVJawR1eMugNor+UWw344x3kD67uR1PmPOZqj+mbwfmfz0U
hkjGciS3Q+f4hr26XcJyNPGMcufQBOZEn1MQeSnsERlzFItrhV8mUb9CLhwBMREb
c3/fyPFE1oyH/ctfAyjRhBvUn9X+AE09yyMeymhfnr3SeFfujXnvA9cJVhNHDzty
hGoDNICXJWHMIWYbGgRclTjpCVr+Qpe7a/5Da5rtIxF/CacISjDMknyIVKhcWMrx
pcfScvyR3Enrdl9e3GrfmKLmYoGqD6ck1sCXE2BrdMOli+cDmGndpWOOLFAw12YM
4BuKvliMC0a7Q3zUW3r8elgyDk6mTqrsZquiEjPQ32fnDjQxBOum4yuy9D5fEibE
CUwkHyxpWieI9DBnEqE9BiZymzk6Qry/mvuPbF5i5UNwn6bObDLu0KHJOYf1UAwY
rqFIWJe99nUUg+w0fHrPln5vrDkW8a+sSOgvY9CNVjTIHSbZRF18fML1tOXiLzr7
T6oIjB9G6liVMlncwdiYotU79uwR+S9mtDcIWy7YC3VTKwIDAQABo0UwQzAOBgNV
HQ8BAf8EBAMCAqQwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQUR47TuhD5
DSubRMt/80T1kV4KKz4wDQYJKoZIhvcNAQELBQADggIBAHNFc31lTXtyRr6B2IZE
qMDztLZ2BTHiNZ+bXdhiwCu5C79RVuZoyRM18k3b6/B+1g10jFoNwVGNzzok+h3h
OORojGWJA0HjN1drnl2cyWQ/MrdAsjvGcJ5X4jcTnm2mAfrg13OylF+iAqwT4CrJ
2oakymcQrXW8pGr2YOEVZEicGIzAAAWFFvWxESkGb2mztriEadLCg1t43EAeIFtM
kQD4+scWUsb/6WOfZ3j15Z7+gWfty7h5nkeEItJIpxWwDhVxlWug0GRdJzmZv1UA
wf66DkA6ulNCDiS/n28NFMRJqEuHwa5QV16YsK4W1kXaYOwa7q7qlThhJu9aznrN
HbXUXT4/6+lp2L8zzuWyllrRjAPqFQ/ZEqKw5sIlgwFaU9YP82Ly9IHIPigm0mtL
XthlWat7zkwxt1+QkwC3ADzrY/DfmX3VrYZBUTjJslTlEgz4OhBr+E5UpmOfLYRm
6NtzcUo9xEYlGuxxLexOXV/tRMZYKuhAPZzQmkuXJarDskewyA4GqdNGIlvFvWbz
HBvlRgSPzKUNromy7v0YihTdYayrJ2gZjokwjaYBeTWVl0+NawtcjsUr9vhVGp94
JsLTgS5vva9pGOWs5PHNiDfx0lIshklgTgr9sNSbIclLMAP0wK8t/U+Ub59EJJBK
GYgjLXpNp4gpO4bQ8ZN2O8Wa
-----END CERTIFICATE-----`

func TestReadCertificateFile_Inline(t *testing.T) {
	inl := fmt.Sprintf("%s%s", storage.InlinePrefix, TestCertPem)
	cert, err := storage.ReadCertificateFile(inl)
	if err != nil {
		t.Errorf("Unexpected err: %v", err)
	}

	if cert.Subject.CommonName != "wcrypto test" {
		t.Errorf("Unexpected CN: %s", cert.Subject.CommonName)
	}
}
