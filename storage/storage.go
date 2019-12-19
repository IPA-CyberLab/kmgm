package storage

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	"github.com/IPA-CyberLab/kmgm/dname"
	"github.com/IPA-CyberLab/kmgm/frontend/validate"
	"github.com/IPA-CyberLab/kmgm/pemparser"
	"github.com/IPA-CyberLab/kmgm/wcrypto"
	"go.uber.org/multierr"
)

type Storage struct {
	BaseDir string
}

func New(baseDir string) (*Storage, error) {
	if err := validate.Dir(baseDir); err != nil {
		return nil, err
	}

	return &Storage{BaseDir: baseDir}, nil
}

func (s *Storage) ClientCACertPath() string {
	return filepath.Join(s.BaseDir, "server.cert.pem")
}

func (s *Storage) ClientPrivateKeyPath() string {
	return filepath.Join(s.BaseDir, "client.key.pem")
}

func (s *Storage) ClientCertPath() string {
	return filepath.Join(s.BaseDir, "client.cert.pem")
}

func (s *Storage) ConnectionInfoPath() string {
	return filepath.Join(s.BaseDir, "connection_info.yaml")
}

type Profile struct {
	BaseDir string
}

// The name of storage profile to be used as default if nothing was specified.
const DefaultProfileName = "default"

func (s *Storage) Profile(name string) (*Profile, error) {
	p := &Profile{
		BaseDir: filepath.Join(s.BaseDir, name),
	}
	if err := validate.Dir(p.BaseDir); err != nil {
		return nil, err
	}

	return p, nil
}

func (p *Profile) String() string {
	if p == nil {
		return "(*Profile)nil"
	}

	return fmt.Sprintf("Profile{%q}", p.BaseDir)
}

func (s *Profile) mkdirIfNeeded() error {
	if err := os.MkdirAll(s.BaseDir, 0755); err != nil {
		return fmt.Errorf("os.MkdirAll(%q): %w", s.BaseDir, err)
	}
	return nil
}

func (s *Profile) CAPrivateKeyPath() string {
	return filepath.Join(s.BaseDir, "priv.pem")
}

func (s *Profile) CACertPath() string {
	return filepath.Join(s.BaseDir, "cacert.pem")
}

func (s *Profile) serverCertPath() string {
	return filepath.Join(s.BaseDir, "server.cert.pem")
}

func (s *Profile) serverPrivateKeyPath() string {
	return filepath.Join(s.BaseDir, "server.priv.pem")
}

func (s *Profile) IssueDBPath() string {
	return filepath.Join(s.BaseDir, "issuedb.json")
}

func CheckFileNotExist(path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("Unhandled os.Stat(%q) error: %w", path, err)
	}
	if fi.IsDir() {
		return fmt.Errorf("Would like to create file %q, but there is a dir of same name.", path)
	}

	return fmt.Errorf("File %q already exists.", path)
}

type CAStatusCode int

const (
	NotCA = iota
	Broken
	Expired
)

type CAStatus struct {
	Code          CAStatusCode
	UnderlyingErr error
}

func (s *CAStatus) Error() string {
	if s == nil {
		return "ValidCA"
	}

	var str string
	switch s.Code {
	case NotCA:
		str = "NotCA"
	case Broken:
		str = "Broken"
	case Expired:
		str = "Expired"
	}

	return fmt.Sprintf("%s: %v", str, s.UnderlyingErr)
}

func (s *CAStatus) Unwrap() error {
	return s.UnderlyingErr
}

func (s *Profile) Status() *CAStatus {
	paths := []string{
		s.CAPrivateKeyPath(),
		s.CACertPath(),
		s.IssueDBPath(),
	}
	notExistCount := 0
	var merr error
	for _, p := range paths {
		if err := CheckFileNotExist(p); err != nil {
			merr = multierr.Append(merr, err)
		} else {
			notExistCount++
		}
	}
	if notExistCount == len(paths) {
		// No existing CA file found.
		return &CAStatus{NotCA, nil}
	} else if notExistCount != 0 {
		// Some CA files are missing.
		return &CAStatus{Broken, merr}
	}
	// All CA files are found.

	capriv, err := s.ReadCAPrivateKey()
	if err != nil {
		return &CAStatus{Broken, err}
	}
	cacert, err := s.ReadCACertificate()
	if err != nil {
		return &CAStatus{Broken, err}
	}
	// FIXME[P2]: check issuedb json?

	if err := wcrypto.VerifyCACertAndKey(capriv, cacert, time.Now()); err != nil {
		// FIXME[P2]: There could be other failure reasons as well
		return &CAStatus{Expired, err}
	}

	return nil
}

func WriteCertificateDerFile(p string, certDer []byte) error {
	certPem := pemparser.MarshalCertificateDer(certDer)
	if err := ioutil.WriteFile(p, certPem, 0644); err != nil {
		return fmt.Errorf("CA cert write to %q failed: %w", p, err)
	}
	return nil
}

func WriteCertificateFile(p string, cert *x509.Certificate) error {
	return WriteCertificateDerFile(p, cert.Raw)
}

func (s *Profile) WriteCACertificateDer(certDer []byte) error {
	if err := s.mkdirIfNeeded(); err != nil {
		return err
	}

	p := s.CACertPath()
	return WriteCertificateDerFile(p, certDer)
}

func (s *Profile) WriteServerCertificate(cert *x509.Certificate) error {
	if err := s.mkdirIfNeeded(); err != nil {
		return err
	}

	p := s.serverCertPath()
	return WriteCertificateFile(p, cert)
}

func ReadCertificateFile(p string) (*x509.Certificate, error) {
	bs, err := ioutil.ReadFile(p)
	if err != nil {
		return nil, fmt.Errorf("Failed to read CA cert %q: %w", p, err)
	}
	cs, err := pemparser.ParseCertificates(bs)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse CA cert %q: %w", p, err)
	}
	if len(cs) != 1 {
		// FIXME[P-]: use the last one?
		return nil, fmt.Errorf("%d CA certs found in %q", len(cs), p)
	}
	return cs[0], nil
}

func (s *Profile) ReadCACertificate() (*x509.Certificate, error) {
	p := s.CACertPath()
	return ReadCertificateFile(p)
}

func (s *Profile) ReadCASubject() (*dname.Config, error) {
	cacert, err := s.ReadCACertificate()
	if err != nil {
		return nil, err
	}

	return dname.FromPkixName(cacert.Subject), nil
}

func (s *Profile) ReadServerCertificate() (*x509.Certificate, error) {
	p := s.serverCertPath()
	return ReadCertificateFile(p)
}

func WritePrivateKeyFile(p string, priv crypto.PrivateKey) error {
	privPem, err := pemparser.MarshalPrivateKey(priv)
	if err != nil {
		return err
	}
	if err := ioutil.WriteFile(p, privPem, 0400); err != nil {
		return fmt.Errorf("Private key write to %q failed: %w", p, err)
	}
	return nil
}

func (s *Profile) WriteCAPrivateKey(priv crypto.PrivateKey) error {
	if err := s.mkdirIfNeeded(); err != nil {
		return err
	}
	p := s.CAPrivateKeyPath()
	return WritePrivateKeyFile(p, priv)
}

func (s *Profile) WriteServerPrivateKey(priv crypto.PrivateKey) error {
	if err := s.mkdirIfNeeded(); err != nil {
		return err
	}
	p := s.serverPrivateKeyPath()
	return WritePrivateKeyFile(p, priv)
}

func ReadPrivateKeyFile(p string) (crypto.PrivateKey, error) {
	bs, err := ioutil.ReadFile(p)
	if err != nil {
		return nil, fmt.Errorf("Failed to read private key %q: %w", p, err)
	}
	priv, err := pemparser.ParsePrivateKey(bs)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse private key %q: %w", p, err)
	}
	return priv, nil
}

func (s *Profile) ReadCAPrivateKey() (crypto.PrivateKey, error) {
	p := s.CAPrivateKeyPath()
	return ReadPrivateKeyFile(p)
}

func (s *Profile) ReadServerPrivateKey() (crypto.PrivateKey, error) {
	p := s.serverPrivateKeyPath()
	return ReadPrivateKeyFile(p)
}
