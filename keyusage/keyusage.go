package keyusage

import (
	"crypto/x509"
	"errors"
	"fmt"
	"sort"

	"github.com/IPA-CyberLab/kmgm/pb"
)

type KeyUsage struct {
	KeyUsage     x509.KeyUsage
	ExtKeyUsages []x509.ExtKeyUsage
}

var KeyUsageCA = KeyUsage{
	KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	// https://tools.ietf.org/html/rfc5280#section-4.2.1.12
	// "In general, this extension will appear only in end entity certificates."
	ExtKeyUsages: nil,
}

var KeyUsageTLSServer = KeyUsage{
	KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
	ExtKeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
}

var KeyUsageTLSClient = KeyUsage{
	KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
	ExtKeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
}

var KeyUsageTLSClientServer = KeyUsage{
	KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
	ExtKeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
}

func (u KeyUsage) Clone() KeyUsage {
	return KeyUsage{
		KeyUsage:     u.KeyUsage,
		ExtKeyUsages: append([]x509.ExtKeyUsage{}, u.ExtKeyUsages...),
	}
}

func (u KeyUsage) Verify() error {
	if int(u.KeyUsage) == 0 {
		return errors.New("KeyUsage is empty.")
	}

	// FIXME[P2]: Implement https://tools.ietf.org/html/rfc5280#section-4.2.1.3

	return nil
}

type yamlKeyUsage struct {
	KeyUsage    []string `yaml:"keyUsage"`
	ExtKeyUsage []string `yaml:"extKeyUsage"`
	Preset      string   `yaml:"preset"`
}

func PresetFromString(s string) (KeyUsage, error) {
	if s == "tlsServer" {
		return KeyUsageTLSServer.Clone(), nil
	} else if s == "tlsClient" {
		return KeyUsageTLSClient.Clone(), nil
	} else if s == "tlsClientServer" {
		return KeyUsageTLSClientServer.Clone(), nil
	} else {
		return KeyUsage{}, fmt.Errorf("Unknown preset %q specified", s)
	}
}

func KeyUsageFromString(bitName string) (x509.KeyUsage, error) {
	// FIXME[P2]: Support more
	switch bitName {
	case "keyEncipherment":
		return x509.KeyUsageKeyEncipherment, nil
	case "digitalSignature":
		return x509.KeyUsageDigitalSignature, nil
	default:
		return x509.KeyUsage(0), fmt.Errorf("unknown bitName %q", bitName)
	}
}

func ExtKeyUsageFromString(ekuName string) (x509.ExtKeyUsage, error) {
	// FIXME[P2]: Support more
	switch ekuName {
	case "any":
		return x509.ExtKeyUsageAny, nil
	case "clientAuth":
		return x509.ExtKeyUsageClientAuth, nil
	case "serverAuth":
		return x509.ExtKeyUsageServerAuth, nil
	default:
		return x509.ExtKeyUsage(0), fmt.Errorf("unknown ekuName %q", ekuName)
	}
}

func (u *KeyUsage) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var yku yamlKeyUsage
	if err := unmarshal(&yku); err != nil {
		return err
	}

	if yku.Preset != "" {
		if len(yku.KeyUsage) != 0 {
			return errors.New("preset and keyUsage is not allowed to be specified at once.")
		}
		if len(yku.ExtKeyUsage) != 0 {
			return errors.New("preset and extKeyUsage is not allowed to be specified at once.")
		}

		var err error
		*u, err = PresetFromString(yku.Preset)
		if err != nil {
			return err
		}
		return nil
	}

	u.KeyUsage = x509.KeyUsage(0)
	for _, ku := range yku.KeyUsage {
		bit, err := KeyUsageFromString(ku)
		if err != nil {
			return err
		}
		u.KeyUsage |= bit
	}

	foundAny := false
	u.ExtKeyUsages = []x509.ExtKeyUsage{}
	for _, ekustr := range yku.ExtKeyUsage {
		eku, err := ExtKeyUsageFromString(ekustr)
		if err != nil {
			return err
		}

		u.ExtKeyUsages = append(u.ExtKeyUsages, eku)
		if eku == x509.ExtKeyUsageAny {
			foundAny = true
		}
	}
	if foundAny && len(u.ExtKeyUsages) > 1 {
		return fmt.Errorf("extKeyUsage \"any\" and other extKeyUsages cannot be specified at once.")
	}

	return nil
}

func FromProtoStruct(s *pb.KeyUsage) KeyUsage {
	if s == nil {
		return KeyUsage{}
	}

	ekus := make([]x509.ExtKeyUsage, 0, len(s.ExtKeyUsages))
	for _, ekuint := range s.ExtKeyUsages {
		ekus = append(ekus, x509.ExtKeyUsage(ekuint))
	}

	return KeyUsage{
		KeyUsage:     x509.KeyUsage(s.KeyUsage),
		ExtKeyUsages: ekus,
	}
}

func (u KeyUsage) ToProtoStruct() *pb.KeyUsage {
	ekuints := make([]uint32, 0, len(u.ExtKeyUsages))
	for _, eku := range u.ExtKeyUsages {
		ekuints = append(ekuints, uint32(eku))
	}

	return &pb.KeyUsage{
		KeyUsage:     uint32(u.KeyUsage),
		ExtKeyUsages: ekuints,
	}
}

func FromCertificate(cert *x509.Certificate) KeyUsage {
	return KeyUsage{
		KeyUsage:     cert.KeyUsage,
		ExtKeyUsages: cert.ExtKeyUsage,
	}
}

func (p *KeyUsage) UnmarshalFlag(s string) error {
	ku, err := PresetFromString(s)
	if err != nil {
		return err
	}

	*p = ku
	return nil
}

func (a KeyUsage) Equals(b KeyUsage) bool {
	if a.KeyUsage != b.KeyUsage {
		return false
	}
	if len(a.ExtKeyUsages) != len(b.ExtKeyUsages) {
		return false
	}

	ekua := append([]x509.ExtKeyUsage{}, a.ExtKeyUsages...)
	ekub := append([]x509.ExtKeyUsage{}, b.ExtKeyUsages...)
	sort.Slice(ekua, func(i, j int) bool { return ekua[i] < ekua[j] })
	sort.Slice(ekub, func(i, j int) bool { return ekub[i] < ekub[j] })
	for i := range ekua {
		if ekua[i] != ekub[i] {
			return false
		}
	}

	return true
}

func (ku KeyUsage) Preset() string {
	if ku.Equals(KeyUsageTLSServer) {
		return "tlsServer"
	}
	if ku.Equals(KeyUsageTLSClient) {
		return "tlsClient"
	}
	if ku.Equals(KeyUsageTLSClientServer) {
		return "tlsClientServer"
	}
	return "custom"
}
