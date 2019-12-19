package dname

import "github.com/IPA-CyberLab/kmgm/pb"

func FromProtoStruct(s *pb.DistinguishedName) *Config {
	if s == nil {
		return &Config{}
	}

	return &Config{
		CommonName:         s.CommonName,
		Organization:       s.Organization,
		OrganizationalUnit: s.OrganizationalUnit,
		Country:            s.Country,
		Locality:           s.Locality,
		Province:           s.Province,
		StreetAddress:      s.StreetAddress,
		PostalCode:         s.PostalCode,
	}
}

func (c *Config) ToProtoStruct() *pb.DistinguishedName {
	return &pb.DistinguishedName{
		CommonName:         c.CommonName,
		Organization:       c.Organization,
		OrganizationalUnit: c.OrganizationalUnit,
		Country:            c.Country,
		Locality:           c.Locality,
		Province:           c.Province,
		StreetAddress:      c.StreetAddress,
		PostalCode:         c.PostalCode,
	}
}
