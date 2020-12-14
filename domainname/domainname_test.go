package domainname_test

import (
	"os"
	"testing"

	"github.com/IPA-CyberLab/kmgm/domainname"
)

func TestDNSDomainname(t *testing.T) {
	dn, err := domainname.DNSDomainname()
	if err != nil {
		// FIXME[P2]: Some hosts simply doesn't have domainname configured...
		// t.Errorf("%v", err)
	}

	hn, _ := os.Hostname()
	t.Logf("os.Hostname: %s", hn)
	t.Logf("dn: %s", dn)
}
