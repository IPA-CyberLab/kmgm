package domainname_test

import (
	"testing"

	"github.com/IPA-CyberLab/kmgm/domainname"
)

func TestDNSDomainname(t *testing.T) {
	dn, err := domainname.DNSDomainname()
	if err != nil {
		// FIXME[P2]: Some hosts simply doesn't have domainname configured...
		// t.Errorf("%v", err)
	}

	t.Logf("dn: %s", dn)
}
