package setup

import (
	"fmt"
	"net"
)

type NameConstraints struct {
	PermittedDNSDomains []string
	ExcludedDNSDomains  []string

	PermittedIPRanges []*net.IPNet
	ExcludedIPRanges  []*net.IPNet
}

func (p *NameConstraints) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var ss []string
	if err := unmarshal(&ss); err != nil {
		return err
	}

	for _, s := range ss {
		excludeRule := false
		if s[0] == '-' {
			excludeRule = true
			s = s[1:]
		} else if s[0] == '+' {
			s = s[1:]
		}

		_, net, err := net.ParseCIDR(s)
		if err == nil {
			if excludeRule {
				p.ExcludedIPRanges = append(p.ExcludedIPRanges, net)
			} else {
				p.PermittedIPRanges = append(p.PermittedIPRanges, net)
			}
		} else {
			if excludeRule {
				p.ExcludedDNSDomains = append(p.ExcludedDNSDomains, s)
			} else {
				p.PermittedDNSDomains = append(p.PermittedDNSDomains, s)
			}
		}
	}
	return nil
}

func (nc *NameConstraints) IsEmpty() bool {
	if len(nc.PermittedDNSDomains) > 0 {
		return false
	}
	if len(nc.ExcludedDNSDomains) > 0 {
		return false
	}
	if len(nc.PermittedIPRanges) > 0 {
		return false
	}
	if len(nc.ExcludedIPRanges) > 0 {
		return false
	}

	return true
}

func (nc *NameConstraints) Strings() []string {
	var ss []string
	for _, e := range nc.PermittedDNSDomains {
		ss = append(ss, fmt.Sprintf("+%s", e))
	}
	for _, e := range nc.ExcludedDNSDomains {
		ss = append(ss, fmt.Sprintf("-%s", e))
	}
	for _, e := range nc.PermittedIPRanges {
		ss = append(ss, fmt.Sprintf("+%v", e))
	}
	for _, e := range nc.ExcludedIPRanges {
		ss = append(ss, fmt.Sprintf("-%v", e))
	}

	return ss
}
