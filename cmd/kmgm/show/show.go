package show

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/manifoldco/promptui"
	"github.com/urfave/cli/v2"

	"github.com/IPA-CyberLab/kmgm/action"
	"github.com/IPA-CyberLab/kmgm/pemparser"
	"github.com/IPA-CyberLab/kmgm/storage"
	"github.com/IPA-CyberLab/kmgm/storage/issuedb"
	"github.com/IPA-CyberLab/kmgm/wcrypto"
)

func HexStr(bs []byte) string {
	if bs == nil {
		return "<nil>"
	}
	if len(bs) == 0 {
		return "<empty>"
	}

	var buf bytes.Buffer
	buf.Grow(len(bs)*3 - 1)

	for i, b := range bs {
		buf.WriteString(fmt.Sprintf("%02X", b))
		if i != len(bs)-1 {
			buf.WriteRune(':')
		}
	}

	return buf.String()
}

var oidsHandled = []asn1.ObjectIdentifier{
	{2, 5, 29, 35}, // AuthorityKeyId
}
var oidKeyUsage = asn1.ObjectIdentifier{2, 5, 29, 15}
var oidSubjectAltName = asn1.ObjectIdentifier{2, 5, 29, 17}
var oidNameConstraints = asn1.ObjectIdentifier{2, 5, 29, 30}
var oidExtKeyUsage = asn1.ObjectIdentifier{2, 5, 29, 37}
var oidBasicConstraints = asn1.ObjectIdentifier{2, 5, 29, 19}

func PrintCertInfo(w io.Writer, cert *x509.Certificate, ft FormatType) {
	if ft.ShouldOutputInfo() {
		fmt.Fprint(w, promptui.Styler(promptui.FGBold)("=== Certificate Info ==="))
		pubkeyhash, err := wcrypto.PubKeyPinString(cert.PublicKey)
		if err != nil {
			pubkeyhash = fmt.Sprintf("Failed to compute public key hash: %s", err)
		}

		// FIXME[P2]: KeyUsage / Extensions info
		fmt.Fprintf(w, `
SerialNumber: %s
Subject: %s
Validity:
  NotBefore: %s
  NotAfter:  %s
PublicKey:
  Algorithm: %s
  Hash: %s
  SubjectKeyId: %s
Issuer: %s
  AuthorityKeyId: %s
SignatureAlgorithm: %s
`,
			cert.SerialNumber,
			cert.Subject,
			cert.NotBefore.Format(time.RFC3339),
			cert.NotAfter.Format(time.RFC3339),
			cert.PublicKeyAlgorithm,
			pubkeyhash,
			HexStr(cert.SubjectKeyId),
			cert.Issuer,
			HexStr(cert.AuthorityKeyId),
			cert.SignatureAlgorithm,
		)

	extL:
		for _, e := range cert.Extensions {
			for _, ignore := range oidsHandled {
				if e.Id.Equal(ignore) {
					continue extL
				}
			}
			if e.Id.Equal(oidSubjectAltName) {
				fmt.Fprintf(w, "SubjectAltNames (marked critical: %t):\n", e.Critical)
				for _, p := range cert.DNSNames {
					fmt.Fprintf(w, "+ DNS: %s\n", p)
				}
				for _, p := range cert.EmailAddresses {
					fmt.Fprintf(w, "+ Email: %s\n", p)
				}
				for _, p := range cert.IPAddresses {
					fmt.Fprintf(w, "+ IP: %v\n", p)
				}
				for _, p := range cert.URIs {
					fmt.Fprintf(w, "+ URI: %v\n", p)
				}
			} else if e.Id.Equal(oidBasicConstraints) {
				fmt.Fprintf(w, "IsCA: %t\n", cert.IsCA)
				if cert.IsCA {
					if cert.MaxPathLen == 0 && !cert.MaxPathLenZero {
						fmt.Fprintf(w, "  MaxPathLen: <nil>\n")
					} else {
						fmt.Fprintf(w, "  MaxPathLen: %d\n", cert.MaxPathLen)
					}
				}
			} else if e.Id.Equal(oidKeyUsage) {
				fmt.Fprintf(w, "KeyUsage (marked critical: %t):\n", e.Critical)
				fmt.Fprintf(w, "- FIXME[P1]: dump keyusage\n")
			} else if e.Id.Equal(oidExtKeyUsage) {
				fmt.Fprintf(w, "ExtKeyUsage (marked critical: %t):\n", e.Critical)
				fmt.Fprintf(w, "- FIXME[P1]: dump extkeyusage\n")
			} else if e.Id.Equal(oidNameConstraints) {
				fmt.Fprintf(w, "Name Constraints (marked critical: %t):\n", e.Critical)
				for _, p := range cert.PermittedDNSDomains {
					fmt.Fprintf(w, "+ DNS: %s\n", p)
				}
				for _, p := range cert.PermittedEmailAddresses {
					fmt.Fprintf(w, "+ Email: %s\n", p)
				}
				for _, p := range cert.PermittedIPRanges {
					fmt.Fprintf(w, "+ IPRange: %v\n", p)
				}
				for _, p := range cert.PermittedURIDomains {
					fmt.Fprintf(w, "+ URIDomains: %v\n", p)
				}
				for _, p := range cert.ExcludedDNSDomains {
					fmt.Fprintf(w, "- DNS: %s\n", p)
				}
				for _, p := range cert.ExcludedEmailAddresses {
					fmt.Fprintf(w, "- Email: %s\n", p)
				}
				for _, p := range cert.ExcludedIPRanges {
					fmt.Fprintf(w, "- IPRange: %v\n", p)
				}
				for _, p := range cert.ExcludedURIDomains {
					fmt.Fprintf(w, "- URIDomains: %v\n", p)
				}
			} else {
				fmt.Fprintf(w, "Unknown Extension (%s)\n", e.Id.String())
			}
		}

		fmt.Fprint(w, "PEM (use `-o pem` to show pem only):\n")
	}
	if ft.ShouldOutputPEM() {
		bs := pemparser.MarshalCertificateDer(cert.Raw)
		w.Write(bs)
	}
}

type FindCertificateWithPrefixType func(ctx context.Context, env *action.Environment, prefix string) (*x509.Certificate, error)

func FindCertificateWithPrefix(ctx context.Context, env *action.Environment, prefix string) (*x509.Certificate, error) {
	slog := env.Logger.Sugar()

	profile, err := env.Profile()
	if err != nil {
		return nil, err
	}

	now := env.NowImpl()
	st := profile.Status(now)
	if st.Code != storage.ValidCA {
		if st.Code == storage.Expired {
			slog.Warnf("Expired %s")
		} else {
			return nil, fmt.Errorf("Could not find a valid CA profile %q: %v", env.ProfileName, st)
		}
	}

	if prefix == "ca" {
		return st.CACert, nil
	}

	db, err := issuedb.New(env.Randr, profile.IssueDBPath())
	if err != nil {
		return nil, err
	}

	es, err := db.Entries()
	if err != nil {
		return nil, err
	}

	matches := make([]issuedb.Entry, 0, 1)
	for _, e := range es {
		idstr := strconv.FormatInt(e.SerialNumber, 10)
		if strings.HasPrefix(idstr, prefix) {
			matches = append(matches, e)
		}
	}

	switch len(matches) {
	case 0:
		return nil, fmt.Errorf("No certificate matches given prefix %q.", prefix)
	case 1:
		e := matches[0]
		pem := []byte(e.CertificatePEM)

		certs, err := pemparser.ParseCertificates(pem)
		if err != nil {
			return nil, fmt.Errorf("error: Failed to parse PEM: %w", err)
		}
		if len(certs) != 1 {
			return nil, fmt.Errorf("error: %d certs found in PEM, expected only one.", len(certs))
		}

		return certs[0], nil
	default:
		idstrs := make([]string, 0, len(matches))
		for _, e := range matches {
			idstr := strconv.FormatInt(e.SerialNumber, 10)
			idstrs = append(idstrs, idstr)
		}
		return nil, fmt.Errorf("Multiple entries matches given prefix %q: %v", prefix, idstrs)
	}
}

func ActionImpl(findCertificateWithPrefixImpl FindCertificateWithPrefixType) func(*cli.Context) error {
	return func(c *cli.Context) error {
		env := action.GlobalEnvironment
		slog := env.Logger.Sugar()

		if c.Args().Len() != 1 {
			slog.Error("Unexpected number of commandline arguments.")
			cli.ShowCommandHelpAndExit(c, "show", 1)
		}
		prefix := c.Args().First()

		fmtstr := c.String("output")
		fmt, err := FormatTypeFromString(fmtstr)
		if err != nil {
			return err
		}

		cert, err := findCertificateWithPrefixImpl(c.Context, env, prefix)
		if err != nil {
			return err
		}

		var w io.Writer
		outfilestr := c.String("file")
		if outfilestr == "-" {
			w = os.Stdout
		} else {
			wf, err := NewIfChangedWriteFile(outfilestr)
			if err != nil {
				wf.Close()
				return err
			}
			defer wf.Close()

			w = wf
		}

		PrintCertInfo(w, cert, fmt)

		return nil
	}
}

var Command = &cli.Command{
	Name:  "show",
	Usage: "Show CA status, an existing certificate and/or its key.",
	UsageText: `kmgm show ca                --- Show the CA certificate.
   kmgm show [serialprefix]    --- Show certificate which has a serial number starting from given prefix.`,
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:    "output",
			Aliases: []string{"o"},
			Usage:   "Output format. (full, pem)",
			Value:   "full",
		},
		&cli.StringFlag{
			Name:    "file",
			Aliases: []string{"f"},
			Usage:   "Write output to specified file.",
			Value:   "-",
		},
	},
	Action: ActionImpl(FindCertificateWithPrefix),
}
