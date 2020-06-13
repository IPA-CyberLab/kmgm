package issuedb_test

import (
	"crypto/rand"
	"io/ioutil"
	"os"
	"testing"

	"github.com/IPA-CyberLab/kmgm/storage/issuedb"
)

func issueDBForTest(t *testing.T) *issuedb.IssueDB {
	t.Helper()

	tmpfile, err := ioutil.TempFile("", "issuedb.json")
	defer os.Remove(tmpfile.Name())
	if err != nil {
		t.Fatalf("ioutil.TempFile: %v", err)
	}

	db, err := issuedb.New(tmpfile.Name())
	if err != nil {
		t.Fatalf("issuedb.New: %v", err)
	}

	return db
}

func TestAllocateSerialNumber(t *testing.T) {
	db := issueDBForTest(t)

	var ns []int64
	for i := 0; i < 16; i++ {
		n, err := db.AllocateSerialNumber(rand.Reader)
		if err != nil {
			t.Fatalf("AllocateSerialNumber failed: %v", err)
		}
		t.Logf("Alloc %d", n)

		ns = append(ns, n)
	}

	for i, n := range ns {
		e, err := db.Query(n)
		if err != nil {
			t.Fatalf("%d: Query(%d) failed: %v", i, n, err)
		}
		if e.State != issuedb.IssueInProgress {
			t.Fatalf("%d: Query(%d) entry unexpected: %+v", i, n, e)
		}
	}
}

func TestIssueCert(t *testing.T) {
	db := issueDBForTest(t)

	n, err := db.AllocateSerialNumber(rand.Reader)
	if err != nil {
		t.Fatalf("AllocateSerialNumber failed: %v", err)
	}
	t.Logf("Alloc %d", n)

	pemDummy := "-----BEGIN CERTIFICATE-----\ndummy\n-----END CERTIFICATE-----\n"

	if err := db.IssueCertificate(n, pemDummy); err != nil {
		t.Fatalf("IssueCertificate failed: %v", err)
	}

	e, err := db.Query(n)
	if err != nil {
		t.Fatalf("Query(%d) failed: %v", n, err)
	}
	if e.CertificatePEM != pemDummy {
		t.Fatalf("pemdiffer: %v", e.CertificatePEM)
	}
}
