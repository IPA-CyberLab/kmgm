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

func TestConfigVerify_Expired(t *testing.T) {
	now := time.Date(2020, time.March, 1, 0, 0, 0, 0, time.UTC)

	cfg := &setup.Config{
		Subject:  &dname.Config{CommonName: "foo"},
		KeyType:  wcrypto.KeyAny,
		Validity: period.ValidityPeriod{NotAfter: now.Add(-1 * time.Hour)},
	}

	if err := cfg.Verify(now); !errors.Is(err, setup.ErrValidityPeriodExpired) {
		t.Errorf("Unexpected: %v", err)
	}
}

func TestConfigVerify_KeyTypeAny(t *testing.T) {
	cfg := &setup.Config{
		Subject:  &dname.Config{CommonName: "foo"},
		KeyType:  wcrypto.KeyAny,
		Validity: period.FarFuture,
	}

	if err := cfg.Verify(time.Now()); !errors.Is(err, setup.ErrKeyTypeAny) {
		t.Errorf("Unexpected: %v", err)
	}
}
