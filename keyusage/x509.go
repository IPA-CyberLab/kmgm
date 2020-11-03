package keyusage

import (
	"crypto/x509"
	"encoding/asn1"
	"fmt"

	"github.com/IPA-CyberLab/kmgm/consts"
)

func FromCSR(req *x509.CertificateRequest) (KeyUsage, error) {
	var ku x509.KeyUsage
	var ekus []x509.ExtKeyUsage

	for _, e := range req.Extensions {
		if e.Id.Equal(consts.OIDExtensionKeyUsage) {
			var bstr asn1.BitString
			if _, err := asn1.Unmarshal(e.Value, &bstr); err != nil {
				return KeyUsage{}, fmt.Errorf("Failed to ans1.Unmarshal keyUsage extension value: %w", err)
			}

			x := 0
			for i := bstr.BitLength - 1; i > -1; i-- {
				x = x << 1
				x = x | bstr.At(i)
			}
			ku = x509.KeyUsage(x)
		} else if e.Id.Equal(consts.OIDExtensionExtendedKeyUsage) {
			var oids []asn1.ObjectIdentifier
			if _, err := asn1.Unmarshal(e.Value, &oids); err != nil {
				return KeyUsage{}, fmt.Errorf("Failed to ans1.Unmarshal extendedKeyUsage extension value: %w", err)
			}

			for _, oid := range oids {
				if oid.Equal(consts.OIDExtKeyUsageClientAuth) {
					ekus = append(ekus, x509.ExtKeyUsageClientAuth)
				} else if oid.Equal(consts.OIDExtKeyUsageServerAuth) {
					ekus = append(ekus, x509.ExtKeyUsageServerAuth)
				} else {
					return KeyUsage{}, fmt.Errorf("Unsupported extendedKeyUsage oid: %v", oid)
				}
			}
		}
	}

	return KeyUsage{
		KeyUsage:     ku,
		ExtKeyUsages: ekus,
	}, nil
}
