package san

import (
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/IPA-CyberLab/kmgm/domainname"
	"golang.org/x/net/idna"
)

var PunyProfile = idna.New(idna.ValidateForRegistration())

func VerifyDNSNameEntry(s string) error {
	// https://tools.ietf.org/html/rfc5280
	// "When the subjectAltName extension contains a domain name system
	// label, the domain name MUST be stored in the dNSName (an IA5String).
	// The name MUST be in the "preferred name syntax", as specified by
	// Section 3.5 of [RFC1034] and as modified by Section 2.1 of
	// [RFC1123].  Note that while uppercase and lowercase letters are
	// allowed in domain names, no significance is attached to the case.  In
	// addition, while the string " " is a legal domain name, subjectAltName
	// extensions with a dNSName of " " MUST NOT be used.  Finally, the use
	// of the DNS representation for Internet mail addresses
	// (subscriber.example.com instead of subscriber@example.com) MUST NOT
	// be used; such identities are to be encoded as rfc822Name.  Rules for
	// encoding internationalized domain names are specified in Section 7.2."
	if s == " " {
		return errors.New("san: Domainname \" \" is not allowed as subjectAltName")
	}
	if strings.HasSuffix(s, ".") {
		return errors.New("san: Domainname should not end with a '.'")
	}

	subdomains := strings.Split(s, ".")
	for _, sd := range subdomains {
		if len(sd) == 0 {
			return errors.New("san: subdomain may not be empty.")
		}
		if sd[0] == '-' {
			return errors.New("san: subdomain may not start with a -")
		}
		for _, r := range sd {
			if ('0' <= r && r <= '9') || ('A' <= r && r <= 'Z') || ('a' <= r && r <= 'z') || r == '-' {
				continue
			}
			return fmt.Errorf("san: subdomain may not contain rune '%c'", r)
		}
	}
	return nil
}

type Names struct {
	DNSNames []string
	IPAddrs  []net.IP
}

func (ns Names) Verify() error {
	for _, dnsn := range ns.DNSNames {
		if err := VerifyDNSNameEntry(dnsn); err != nil {
			return fmt.Errorf("Invalid DNSName %q: %w", dnsn, err)
		}
	}
	return nil
}

func (ns Names) String() (s string) {
	s = strings.Join(ns.DNSNames, ",")
	for _, a := range ns.IPAddrs {
		s += fmt.Sprintf(",%v", a)
	}
	return
}

func (ns Names) Empty() bool {
	return len(ns.DNSNames) == 0 && len(ns.IPAddrs) == 0
}

// Add parses s and adds the parsed subjectAltName to ns.
// It wont report duplicated entries as its error.
func (ns *Names) Add(s string) error {
	s = strings.ToLower(strings.Trim(s, " "))

	if ipaddr := net.ParseIP(s); ipaddr != nil {
		// check for dups
		for _, e := range ns.IPAddrs {
			if ipaddr.Equal(e) {
				return nil
			}
		}

		ns.IPAddrs = append(ns.IPAddrs, ipaddr)
		return nil
	}

	s, err := PunyProfile.ToASCII(s)
	if err != nil {
		return err
	}

	if err := VerifyDNSNameEntry(s); err != nil {
		return err
	}

	// check for dups
	for _, e := range ns.DNSNames {
		if e == s {
			return nil
		}
	}
	ns.DNSNames = append(ns.DNSNames, s)
	return nil
}

func Parse(s string) (ns Names, err error) {
	ss := strings.Split(s, ",")
	for _, s := range ss {
		err = ns.Add(s)
		if err != nil {
			return
		}
	}

	return
}

func (ns *Names) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var ss []string
	if err := unmarshal(&ss); err != nil {
		return err
	}

	*ns = Names{}
	for _, s := range ss {
		if err := ns.Add(s); err != nil {
			return err
		}
	}

	return nil
}

func FromCertificate(cert *x509.Certificate) Names {
	return Names{
		DNSNames: append([]string{}, cert.DNSNames...),
		IPAddrs:  append([]net.IP{}, cert.IPAddresses...),
	}
}

// FIXME[P2]: should be ForThisListenAddr
// FIXME[P2]: Split. ns := ForThisHost, ns2 := FromListenAddr, ns = ns.Merge(ns2)
func ForThisHost(listenAddr string) (ns Names) {
	if host, _, err := net.SplitHostPort(listenAddr); err == nil {
		if ipaddr := net.ParseIP(host); ipaddr != nil {
			if !ipaddr.IsUnspecified() {
				ns.IPAddrs = append(ns.IPAddrs, ipaddr)
			}
		} else {
			_ = ns.Add(host)
		}
	}
	if len(ns.IPAddrs) == 0 {
		if addrs, err := net.InterfaceAddrs(); err == nil {
			for _, addr := range addrs {
				if ipaddr, ok := addr.(*net.IPNet); ok {
					ip := ipaddr.IP
					if ip.IsLinkLocalUnicast() {
						continue
					}
					ns.IPAddrs = append(ns.IPAddrs, ip)
				}
			}
		}
	}

	hostname, err := os.Hostname()
	if err == nil {
		ns.DNSNames = append(ns.DNSNames, hostname)
	}
	if domainname, err := domainname.DNSDomainname(); err == nil {
		ns.DNSNames = append(ns.DNSNames, fmt.Sprintf("%s.%s", hostname, domainname))
	}

	return
}

func (p *Names) UnmarshalFlag(s string) error {
	ns, err := Parse(s)
	if err != nil {
		return err
	}

	*p = ns
	return nil
}
