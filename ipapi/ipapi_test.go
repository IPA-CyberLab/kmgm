package ipapi_test

import (
	"testing"

	"github.com/IPA-CyberLab/kmgm/ipapi"
)

func TestQuery(t *testing.T) {
	r, err := ipapi.Query()
	if err != nil {
		t.Fatalf("ipapi.Query: %v", err)
	}

	t.Logf("%+v", r)
}
