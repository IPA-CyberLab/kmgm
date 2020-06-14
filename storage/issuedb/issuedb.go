package issuedb

import (
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"

	"github.com/IPA-CyberLab/kmgm/pemparser"
	"github.com/gofrs/flock"
)

var ErrNotExist = errors.New("issuedb: Entry does not exist.")

type Entry struct {
	SerialNumber   int64  `json:"sn"`
	State          State  `json:"state"`
	CertificatePEM string `json:"certPem"`
}

func (e *Entry) ParseCertificate() (*x509.Certificate, error) {
	pem := []byte(e.CertificatePEM)
	certs, err := pemparser.ParseCertificates(pem)
	if err != nil {
		return nil, err
	}
	if len(certs) != 1 {
		return nil, fmt.Errorf("issuedb: Expected 1 cert pem, found %d certs.", len(certs))
	}
	return certs[0], nil
}

func RandInt63(randr io.Reader) (n int64) {
	if err := binary.Read(randr, binary.LittleEndian, &n); err != nil {
		panic(err)
	}
	if n < 0 {
		n = -n
	}
	return
}

type IssueDB struct {
	jsonFilePath string
}

func New(jsonFilePath string) (*IssueDB, error) {
	return &IssueDB{
		jsonFilePath: jsonFilePath,
	}, nil
}

func (db *IssueDB) Initialize() error {
	fl := flock.New(db.jsonFilePath)
	if err := fl.Lock(); err != nil {
		return fmt.Errorf("Failed to acquire issuedb flock: %w", err)
	}
	defer fl.Unlock()

	es, err := db.entriesWithLock()
	if err != nil {
		return err
	}

	if len(es) > 0 {
		return fmt.Errorf("Tried to initialize issuedb, but found %d existing entries", len(es))
	}
	if err := ioutil.WriteFile(db.jsonFilePath, []byte("[]"), 0644); err != nil {
		return err
	}

	return nil
}

func (db *IssueDB) entriesWithLock() ([]Entry, error) {
	bs, err := ioutil.ReadFile(db.jsonFilePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrNotExist
		}
		return nil, fmt.Errorf("Failed to open issuedb json: %w", err)
	}

	var es []Entry
	if len(bs) != 0 {
		if err := json.Unmarshal(bs, &es); err != nil {
			return nil, fmt.Errorf("Failed to unmarshal issuedb json: %w", err)
		}
	}

	return es, nil
}

func (db *IssueDB) Entries() ([]Entry, error) {
	fl := flock.New(db.jsonFilePath)
	if err := fl.Lock(); err != nil {
		return nil, fmt.Errorf("Failed to acquire issuedb flock: %w", err)
	}
	defer fl.Unlock()

	return db.entriesWithLock()
}

func (db *IssueDB) setEntry(ne Entry) error {
	fl := flock.New(db.jsonFilePath)
	if err := fl.Lock(); err != nil {
		return fmt.Errorf("Failed to acquire issuedb flock: %w", err)
	}
	defer fl.Unlock()

	es, err := db.entriesWithLock()
	if err != nil {
		return err
	}

	found := false
	for i, e := range es {
		if e.SerialNumber == ne.SerialNumber {
			found = true

			if err := validateStateTransfer(e.State, ne.State); err != nil {
				return err
			}

			es[i] = ne
			break
		}
	}
	if !found {
		es = append(es, ne)
	}

	bs, err := json.MarshalIndent(es, "", "  ")
	if err != nil {
		return err
	}

	if err := ioutil.WriteFile(db.jsonFilePath, bs, 0644); err != nil {
		return err
	}
	return nil
}

func (db *IssueDB) Query(n int64) (Entry, error) {
	es, err := db.Entries()
	if err != nil {
		return Entry{}, err
	}

	for _, e := range es {
		if e.SerialNumber == n {
			return e, nil
		}
	}

	return Entry{}, ErrNotExist
}

func (db *IssueDB) AllocateSerialNumber(randr io.Reader) (int64, error) {
	// Serial number must be unique and unpredictable. We use a random 63-bit int here.
	// (see https://crypto.stackexchange.com/questions/257/unpredictability-of-x-509-serial-number)

	var n int64
	for {
		n = RandInt63(randr)

		_, err := db.Query(n)
		if err != nil {
			if errors.Is(err, ErrNotExist) {
				break
			}
			return -1, err
		}
		// if err == nil {
		//   there's already an entry, so continue search for next num.
		// }
	}

	if err := db.setEntry(Entry{SerialNumber: n, State: IssueInProgress}); err != nil {
		return -1, err
	}
	return n, nil
}

func (db *IssueDB) IssueCertificate(n int64, pem string) error {
	if err := db.setEntry(Entry{
		SerialNumber:   n,
		State:          ActiveCertificate,
		CertificatePEM: pem,
	}); err != nil {
		return err
	}
	return nil
}
