package show

import (
	"bytes"
	"context"
	"crypto/x509"
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

func PrintCertInfo(w io.Writer, cacert *x509.Certificate, ft FormatType) {
	if ft.ShouldOutputInfo() {
		fmt.Fprint(w, promptui.Styler(promptui.FGBold)("=== Certificate Info ==="))
		pubkeyhash, err := wcrypto.PubKeyPinString(cacert.PublicKey)
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
			cacert.SerialNumber,
			cacert.Subject,
			cacert.NotBefore.Format(time.RFC3339),
			cacert.NotAfter.Format(time.RFC3339),
			cacert.PublicKeyAlgorithm,
			pubkeyhash,
			HexStr(cacert.SubjectKeyId),
			cacert.Issuer,
			HexStr(cacert.AuthorityKeyId),
			cacert.SignatureAlgorithm,
		)
		fmt.Fprint(w, "PEM (use `kmgm show -o pem` to show pem only):\n")
	}
	if ft.ShouldOutputPEM() {
		bs := pemparser.MarshalCertificateDer(cacert.Raw)
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
