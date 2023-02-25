package setup_test

import (
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/IPA-CyberLab/kmgm/action/setup"
)

func TestNameConstraints_UnmarshalYAML(t *testing.T) {
	src := `
- example.org
- 192.0.2.0/24
- 2001:db8:1::/48
- -10.0.0.0/8
- "-bad.example"
- "+ipa.go.jp"
`

	var nc setup.NameConstraints
	if err := yaml.Unmarshal([]byte(src), &nc); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	actual := nc.Strings()
	expected := strings.Split("+example.org +ipa.go.jp -bad.example +192.0.2.0/24 +2001:db8:1::/48 -10.0.0.0/8", " ")
	if !reflect.DeepEqual(actual, expected) {
		t.Errorf("unexp: %s", actual)
	}

	remarshaled, err := yaml.Marshal(actual)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var nc2 setup.NameConstraints
	if err := yaml.Unmarshal(remarshaled, &nc2); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if !reflect.DeepEqual(nc, nc2) {
		t.Errorf("noneq")
	}
}
