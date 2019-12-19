package dname

import (
	"crypto/x509/pkix"
	"fmt"
	"os"

	"go.uber.org/zap"

	"github.com/IPA-CyberLab/kmgm/domainname"
	"github.com/IPA-CyberLab/kmgm/frontend"
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

func DefaultConfig(cnsuffix string, basecfg *Config) (*Config, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return nil, fmt.Errorf("os.Hostname: %w", err)
	}

	if basecfg != nil {
		cfg := &Config{
			CommonName:         hostname + cnsuffix,
			Organization:       basecfg.Organization,
			OrganizationalUnit: basecfg.OrganizationalUnit,
			Country:            basecfg.Country,
			Locality:           basecfg.Locality,
			Province:           basecfg.Province,
			StreetAddress:      basecfg.StreetAddress,
			PostalCode:         basecfg.PostalCode,
		}
		return cfg, nil
	}

	domainname, _ := domainname.DNSDomainname()

	geo, err := ipapi.Query()
	if err != nil {
		zap.S().Infow("ipapi.Query failed", "err", err)
		geo = &ipapi.Result{}
	}

	cfg := &Config{
		CommonName:         hostname + cnsuffix,
		Organization:       domainname,
		OrganizationalUnit: "",
		Country:            geo.CountryCode,
		Locality:           "", // geo.City, but often not accurate enough
		Province:           geo.RegionName,
		StreetAddress:      "",
		PostalCode:         "", // geo.Zip, but often not accurate enough
	}
	return cfg, nil
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

func (cfg *Config) ConfigItems() []frontend.ConfigItem {
	return []frontend.ConfigItem{
		frontend.ConfigItem{
			Label:    "CommonName",
			Validate: validate.PKIXElement(64),
			Value:    &cfg.CommonName,
		},
		frontend.ConfigItem{
			Label:    "Organization",
			Validate: validate.PKIXElement(64),
			Value:    &cfg.Organization,
		},
		frontend.ConfigItem{
			Label:    "OrganizationalUnit",
			Validate: validate.PKIXElement(64),
			Value:    &cfg.OrganizationalUnit,
		},
		frontend.ConfigItem{
			Label:    "Country",
			Validate: validate.PKIXElement(2),
			Value:    &cfg.Country,
		},
		frontend.ConfigItem{
			Label:    "Locality",
			Validate: validate.PKIXElement(128),
			Value:    &cfg.Locality,
		},
		frontend.ConfigItem{
			Label:    "Province",
			Validate: validate.PKIXElement(128),
			Value:    &cfg.Province,
		},
		frontend.ConfigItem{
			Label:    "StreetAddress",
			Validate: validate.PKIXElement(128),
			Value:    &cfg.StreetAddress,
		},
		frontend.ConfigItem{
			Label:    "PostalCode",
			Validate: validate.PKIXElement(40),
			Value:    &cfg.PostalCode,
		},
	}
}
