package domainname

var MockResult string

func DNSDomainname() (string, error) {
	if MockResult != "" {
		return MockResult, nil
	}

	return dnsdomainname()
}
