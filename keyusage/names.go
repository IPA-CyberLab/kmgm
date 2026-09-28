package keyusage

import (
	"crypto/x509"
	"fmt"
)

// keyUsageBitNames lists the KeyUsage bits in bit order, named after
// https://tools.ietf.org/html/rfc5280#section-4.2.1.3
var keyUsageBitNames = []struct {
	Bit  x509.KeyUsage
	Name string
}{
	{x509.KeyUsageDigitalSignature, "digitalSignature"},
	{x509.KeyUsageContentCommitment, "contentCommitment"},
	{x509.KeyUsageKeyEncipherment, "keyEncipherment"},
	{x509.KeyUsageDataEncipherment, "dataEncipherment"},
	{x509.KeyUsageKeyAgreement, "keyAgreement"},
	{x509.KeyUsageCertSign, "keyCertSign"},
	{x509.KeyUsageCRLSign, "cRLSign"},
	{x509.KeyUsageEncipherOnly, "encipherOnly"},
	{x509.KeyUsageDecipherOnly, "decipherOnly"},
}

// KeyUsageNames returns the names of the bits set in ku.
func KeyUsageNames(ku x509.KeyUsage) []string {
	var names []string
	for _, e := range keyUsageBitNames {
		if ku&e.Bit != 0 {
			names = append(names, e.Name)
			ku &^= e.Bit
		}
	}
	for i := 0; ku != 0; i++ {
		if ku&1 != 0 {
			names = append(names, fmt.Sprintf("unknown(bit %d)", i))
		}
		ku >>= 1
	}
	return names
}

var extKeyUsageNames = map[x509.ExtKeyUsage]string{
	x509.ExtKeyUsageAny:                            "any",
	x509.ExtKeyUsageServerAuth:                     "serverAuth",
	x509.ExtKeyUsageClientAuth:                     "clientAuth",
	x509.ExtKeyUsageCodeSigning:                    "codeSigning",
	x509.ExtKeyUsageEmailProtection:                "emailProtection",
	x509.ExtKeyUsageIPSECEndSystem:                 "ipsecEndSystem",
	x509.ExtKeyUsageIPSECTunnel:                    "ipsecTunnel",
	x509.ExtKeyUsageIPSECUser:                      "ipsecUser",
	x509.ExtKeyUsageTimeStamping:                   "timeStamping",
	x509.ExtKeyUsageOCSPSigning:                    "OCSPSigning",
	x509.ExtKeyUsageMicrosoftServerGatedCrypto:     "microsoftServerGatedCrypto",
	x509.ExtKeyUsageNetscapeServerGatedCrypto:      "netscapeServerGatedCrypto",
	x509.ExtKeyUsageMicrosoftCommercialCodeSigning: "microsoftCommercialCodeSigning",
	x509.ExtKeyUsageMicrosoftKernelCodeSigning:     "microsoftKernelCodeSigning",
}

// ExtKeyUsageName returns the name of eku.
func ExtKeyUsageName(eku x509.ExtKeyUsage) string {
	if name, ok := extKeyUsageNames[eku]; ok {
		return name
	}
	return fmt.Sprintf("unknown(%d)", int(eku))
}
