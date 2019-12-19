package san_test

import (
	"net"
	"testing"

	"github.com/IPA-CyberLab/kmgm/san"
)

func TestAdd(t *testing.T) {
	var ns san.Names

	if err := ns.Add("192.168.0.1"); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(ns.IPAddrs) != 1 {
		t.Fatalf("unexpected")
	}

	if err := ns.Add("example.com"); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(ns.IPAddrs) != 1 {
		t.Fatalf("unexpected")
	}
	if len(ns.DNSNames) != 1 {
		t.Fatalf("unexpected")
	}

	if err := ns.Add("example.com"); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(ns.DNSNames) != 1 {
		t.Fatalf("unexpected")
	}
}

func TestPunycode(t *testing.T) {
	var ns san.Names

	if err := ns.Add("日本語.example"); err != nil {
		t.Fatalf("unexpected: %v", err)
	}

	if len(ns.DNSNames) != 1 {
		t.Fatalf("unexpected")
	}
	if ns.DNSNames[0] != "xn--wgv71a119e.example" {
		t.Fatalf("unexpected: %q", ns.DNSNames[0])
	}
}

func TestForThisHost_IPAddr(t *testing.T) {
	ns := san.ForThisHost("192.168.0.100:12345")
	if len(ns.IPAddrs) != 1 {
		t.Fatalf("unexpected len: %d", len(ns.IPAddrs))
	}
	exp := net.ParseIP("192.168.0.100")
	if !ns.IPAddrs[0].Equal(exp) {
		t.Fatalf("unexpected ip: %v", ns.IPAddrs[0])
	}
}

func TestForThisHost_0000(t *testing.T) {
	ns := san.ForThisHost("0.0.0.0:12345")
	if len(ns.IPAddrs) == 0 {
		t.Fatalf("unexpected len: %d", len(ns.IPAddrs))
	}
	inv := net.ParseIP("192.168.0.100")
	for _, ip := range ns.IPAddrs {
		if ip.Equal(inv) {
			t.Fatalf("unexpected ip: %v", ip)
		}
	}
}

func TestForThisHost_Empty(t *testing.T) {
	ns := san.ForThisHost(":12345")
	if len(ns.IPAddrs) == 0 {
		t.Fatalf("unexpected len: %d", len(ns.IPAddrs))
	}
	inv := net.ParseIP("192.168.0.100")
	for _, ip := range ns.IPAddrs {
		if ip.Equal(inv) {
			t.Fatalf("unexpected ip: %v", ip)
		}
	}
}
