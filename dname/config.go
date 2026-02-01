package dname

import (
	"crypto/x509/pkix"
	"fmt"
	"os"

	"go.uber.org/multierr"

	"github.com/IPA-CyberLab/kmgm/domainname"
	"github.com/IPA-CyberLab/kmgm/frontend/validate"
	"github.com/IPA-CyberLab/kmgm/ipapi"
)

type Config struct {
	CommonName         string `yaml:"commonName" flags:"common-name,set cert subject CommonName,cn"`
	Organization       string `yaml:"organization" flags:"organization,set cert subject Organization,org"`
	OrganizationalUnit string `yaml:"organizationalUnit" flags:"organizational-unit,set cert subject OrganizationalUnit,ou"`

	Country       string `yaml:"country" flags:"country,set cert subject Country,c"`
	Locality      string `yaml:"locality" flags:"locality,set cert subject Locality"`
	Province      string `yaml:"province" flags:"province,set cert subject Province"`
	StreetAddress string `yaml:"streetAddress" flags:"street-address,set cert subject StreetAddress"`
	PostalCode    string `yaml:"postalCode" flags:"postal-code,set cert subject PostalCode"`
}

func FromGeoip(geo *ipapi.Result) *Config {
	domainname, _ := domainname.DNSDomainname()

	geo, err := ipapi.Query()
	if err != nil {
		geo = &ipapi.Result{}
	}

	return &Config{
		Organization:       domainname,
		OrganizationalUnit: "",
		Country:            geo.CountryCode,
		Locality:           "", // geo.City, but often not accurate enough
		Province:           geo.RegionName,
		StreetAddress:      "",
		PostalCode:         "", // geo.Zip, but often not accurate enough
	}
}

func DefaultConfig(cnsuffix string, basecfg *Config) *Config {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknownhost"
	}

	if basecfg == nil {
		basecfg = &Config{}
	}

	cn := hostname + cnsuffix
	// trim cn to last 64 chars
	cn = cn[len(cn)-min(len(cn), 64):]

	return &Config{
		CommonName:         cn,
		Organization:       basecfg.Organization,
		OrganizationalUnit: basecfg.OrganizationalUnit,
		Country:            basecfg.Country,
		Locality:           basecfg.Locality,
		Province:           basecfg.Province,
		StreetAddress:      basecfg.StreetAddress,
		PostalCode:         basecfg.PostalCode,
	}
}

func (cfg *Config) ToPkixName() (n pkix.Name) {
	n.CommonName = cfg.CommonName
	if cfg.Organization != "" {
		n.Organization = []string{cfg.Organization}
	}
	if cfg.OrganizationalUnit != "" {
		n.OrganizationalUnit = []string{cfg.OrganizationalUnit}
	}
	if cfg.Country != "" {
		n.Country = []string{cfg.Country}
	}
	if cfg.Locality != "" {
		n.Locality = []string{cfg.Locality}
	}
	if cfg.Province != "" {
		n.Province = []string{cfg.Province}
	}
	if cfg.StreetAddress != "" {
		n.StreetAddress = []string{cfg.StreetAddress}
	}
	if cfg.PostalCode != "" {
		n.PostalCode = []string{cfg.PostalCode}
	}
	return
}

func FromPkixName(n pkix.Name) *Config {
	cfg := &Config{
		CommonName: n.CommonName,
	}
	if len(n.Organization) > 0 {
		cfg.Organization = n.Organization[0]
	}
	if len(n.OrganizationalUnit) > 0 {
		cfg.OrganizationalUnit = n.OrganizationalUnit[0]
	}
	if len(n.Country) > 0 {
		cfg.Country = n.Country[0]
	}
	if len(n.Locality) > 0 {
		cfg.Locality = n.Locality[0]
	}
	if len(n.Province) > 0 {
		cfg.Province = n.Province[0]
	}
	if len(n.StreetAddress) > 0 {
		cfg.StreetAddress = n.StreetAddress[0]
	}
	if len(n.PostalCode) > 0 {
		cfg.PostalCode = n.PostalCode[0]
	}
	return cfg
}

func (cfg *Config) Verify() error {
	if err := validate.PKIXElement(64)(cfg.CommonName); err != nil {
		return fmt.Errorf("CommonName: %w", err)
	}
	if err := validate.PKIXElement(64)(cfg.Organization); err != nil {
		return fmt.Errorf("Organization: %w", err)
	}
	if err := validate.PKIXElement(64)(cfg.OrganizationalUnit); err != nil {
		return fmt.Errorf("OrganizationalUnit: %w", err)
	}
	if err := validate.PKIXElement(2)(cfg.Country); err != nil {
		return fmt.Errorf("Country: %w", err)
	}
	if err := validate.PKIXElement(128)(cfg.Locality); err != nil {
		return fmt.Errorf("Locality: %w", err)
	}
	if err := validate.PKIXElement(128)(cfg.Province); err != nil {
		return fmt.Errorf("Province: %w", err)
	}
	if err := validate.PKIXElement(128)(cfg.StreetAddress); err != nil {
		return fmt.Errorf("StreetAddress: %w", err)
	}
	if err := validate.PKIXElement(128)(cfg.PostalCode); err != nil {
		return fmt.Errorf("PostalCode: %w", err)
	}

	return nil
}

func (cfg *Config) IsEmpty() bool {
	if cfg.CommonName != "" {
		return false
	}
	if cfg.Organization != "" {
		return false
	}
	if cfg.OrganizationalUnit != "" {
		return false
	}
	if cfg.Country != "" {
		return false
	}
	if cfg.Locality != "" {
		return false
	}
	if cfg.Province != "" {
		return false
	}
	if cfg.StreetAddress != "" {
		return false
	}
	if cfg.PostalCode != "" {
		return false
	}

	return true
}

func (a *Config) CompatibleWith(b *Config) error {
	var merr error
	if a.CommonName != b.CommonName {
		merr = multierr.Append(merr, fmt.Errorf("CommonName %q != %q", a.CommonName, b.CommonName))
	}
	if a.Organization != b.Organization {
		merr = multierr.Append(merr, fmt.Errorf("Organization %q != %q", a.Organization, b.Organization))
	}
	if a.OrganizationalUnit != b.OrganizationalUnit {
		merr = multierr.Append(merr, fmt.Errorf("OrganizationalUnit %q != %q", a.OrganizationalUnit, b.OrganizationalUnit))
	}
	if a.Country != b.Country {
		merr = multierr.Append(merr, fmt.Errorf("Country %q != %q", a.Country, b.Country))
	}
	if a.Locality != b.Locality {
		merr = multierr.Append(merr, fmt.Errorf("Locality %q != %q", a.Locality, b.Locality))
	}
	if a.Province != b.Province {
		merr = multierr.Append(merr, fmt.Errorf("Province %q != %q", a.Province, b.Province))
	}
	if a.StreetAddress != b.StreetAddress {
		merr = multierr.Append(merr, fmt.Errorf("StreetAddress %q != %q", a.StreetAddress, b.StreetAddress))
	}
	if a.PostalCode != b.PostalCode {
		merr = multierr.Append(merr, fmt.Errorf("PostalCode %q != %q", a.PostalCode, b.PostalCode))
	}
	return merr
}

func (c *Config) Clone() *Config {
	return &Config{
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
