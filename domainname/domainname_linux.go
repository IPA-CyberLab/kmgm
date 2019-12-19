// +build linux

package domainname

import (
	"fmt"
	"net"
	"os"
	"strings"
)

func DNSDomainname() (string, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return "", fmt.Errorf("os.Hostname: %w", err)
	}

	addrs, err := net.LookupHost(hostname)
	if err != nil {
		return "", fmt.Errorf("net.LookupHost(%q): %w", hostname, err)
	}

	names, err := net.LookupAddr(addrs[0])
	if err != nil {
		return "", fmt.Errorf("net.LookupAddr: %w", err)
	}

	for _, e := range names {
		// trim trailing '.'s
		e := strings.TrimRight(e, ".")

		// trim hostname+'.'
		i := strings.Index(e, ".")
		if i < 0 {
			continue
		}
		e = e[i+1:]

		return e, nil
	}

	return "", fmt.Errorf("FQDN not found from name list %v", names)
}
