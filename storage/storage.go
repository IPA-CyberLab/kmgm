package storage

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

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

func (s *Storage) ClientPrivateKeyPath() string {
	return filepath.Join(s.BaseDir, "client.key.pem")
}

func (s *Storage) ClientCertPath() string {
	return filepath.Join(s.BaseDir, "client.cert.pem")
}

func (s *Storage) ConnectionInfoPath() string {
	return filepath.Join(s.BaseDir, "connection_info.yaml")
}

func (s *Storage) mkdirIfNeeded() error {
	if err := os.MkdirAll(s.BaseDir, 0755); err != nil {
		return fmt.Errorf("os.MkdirAll(%q): %w", s.BaseDir, err)
	}
	return nil
}

func (s *Storage) GeoIpCachePath() string {
	_ = s.mkdirIfNeeded()
	return filepath.Join(s.BaseDir, "geoip_cache.json")
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
		return nil, fmt.Errorf("Failed to open Profile %q: %w", name, err)
	}

	return p, nil
}

func (s *Storage) Profiles() ([]*Profile, error) {
	fis, err := ioutil.ReadDir(s.BaseDir)
	if err != nil {
		return nil, err
	}

	var ps []*Profile
	for _, fi := range fis {
		p, err := s.Profile(fi.Name())
		if err != nil {
			continue
		}

		ps = append(ps, p)
	}

	return ps, nil
}

func (p *Profile) String() string {
	if p == nil {
		return "(*Profile)nil"
	}

	return fmt.Sprintf("Profile{%q}", p.BaseDir)
}

func (p *Profile) Name() string {
	return filepath.Base(p.BaseDir)
}

func (p *Profile) mkdirIfNeeded() error {
	if err := os.MkdirAll(p.BaseDir, 0755); err != nil {
		return fmt.Errorf("os.MkdirAll(%q): %w", p.BaseDir, err)
	}
	return nil
}

func (s *Profile) CAPrivateKeyPath() string {
	return filepath.Join(s.BaseDir, "cakey.pem")
}

func (s *Profile) CACertPath() string {
	return filepath.Join(s.BaseDir, "cacert.pem")
}

func (s *Profile) serverCertPath() string {
	return filepath.Join(s.BaseDir, "server.cert.pem")
}

func (s *Profile) serverPrivateKeyPath() string {
	return filepath.Join(s.BaseDir, "server.key.pem")
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
	ValidCA = iota
	NotCA
	Broken
	Expired
)

type CAStatus struct {
	Profile *Profile
	Code    CAStatusCode
	CACert  *x509.Certificate
	Err     error
}

func (s *CAStatus) addError(err error) {
	s.Err = multierr.Append(s.Err, err)
}

func (s *CAStatus) Error() string {
	var str string
	switch s.Code {
	case ValidCA:
		if s.Err != nil {
			panic("ValidCA should not have any errors")
		}
		return "ValidCA"
	case NotCA:
		str = fmt.Sprintf("Most likely the CA is not setup yet. No CA files found at %q", s.Profile.BaseDir)
	case Broken:
		str = "The CA is broken. Some of essential files are missing."
	case Expired:
		str = "The CA has an expired certificate."
	}

	if s.Err != nil {
		return fmt.Sprintf("%s: %v", str, s.Err)
	}
	return str
}

func (s *CAStatus) Unwrap() error {
	return s.Err
}

func (s *Profile) Status(now time.Time) (st *CAStatus) {
	st = &CAStatus{
		Profile: s,
		Code:    ValidCA,
		CACert:  nil,
		Err:     nil,
	}

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
		st.Code = NotCA
		return
	} else if notExistCount != 0 {
		// Some CA files are missing.
		st.Code = Broken
		st.addError(merr)
		return
	}
	// All CA files are found.

	capriv, err := s.ReadCAPrivateKey()
	if err != nil {
		st.Code = Broken
		st.addError(err)
	}
	cacert, err := s.ReadCACertificate()
	if err != nil {
		st.Code = Broken
		st.addError(err)
	} else {
		st.CACert = cacert
	}
	// FIXME[P2]: check issuedb json?

	if capriv != nil && cacert != nil {
		if err := wcrypto.VerifyCACertAndKey(capriv, cacert, now); err != nil {
			// FIXME[P2]: There could be other failure reasons as well
			st.Code = Expired
			st.addError(err)
		}
	}

	return
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
		return nil, fmt.Errorf("Failed to read CA cert: %w", err)
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
