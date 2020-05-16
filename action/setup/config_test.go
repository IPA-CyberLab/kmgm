package setup_test

import (
	"errors"
	"testing"
	"time"

	"github.com/IPA-CyberLab/kmgm/action/setup"
	"github.com/IPA-CyberLab/kmgm/dname"
	"github.com/IPA-CyberLab/kmgm/period"
	"github.com/IPA-CyberLab/kmgm/wcrypto"
)

func TestConfigVerify_SubjectEmpty(t *testing.T) {
	cfg := &setup.Config{
		Subject:  &dname.Config{},
		KeyType:  wcrypto.KeyRSA4096,
		Validity: period.FarFuture,
	}

	if err := cfg.Verify(time.Now()); !errors.Is(err, setup.ErrSubjectEmpty) {
		t.Errorf("Unexpected: %v", err)
	}
}
