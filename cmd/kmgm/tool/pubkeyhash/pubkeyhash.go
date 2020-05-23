package pubkeyhash

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"reflect"
	"strings"

	"github.com/urfave/cli/v2"
	"go.uber.org/zap"

	"github.com/IPA-CyberLab/kmgm/action"
	"github.com/IPA-CyberLab/kmgm/pemparser"
	"github.com/IPA-CyberLab/kmgm/wcrypto"
)

type KeyHash struct {
	Label string
	Hash  string
}

func ExtractPublicKeyHashesFromPem(bs []byte, logger *zap.Logger) ([]KeyHash, error) {
	slog := logger.Sugar()

	khs := make([]KeyHash, 0)
	err := pemparser.ForeachPemBlock(bs, func(b *pem.Block) error {
		label := ""
		var pub crypto.PublicKey

		if priv, err := pemparser.ParseSinglePrivateKeyBlock(b); err == nil {
			label = fmt.Sprintf("PrivateKey Type=%q", b.Type)
			pub, err = wcrypto.ExtractPublicKey(priv)
			if err != nil {
				return err
			}
		} else {
			switch b.Type {
			case pemparser.CertificatePemType:
				cert, err := x509.ParseCertificate(b.Bytes)
				if err != nil {
					slog.Errorf("Failed to parse a %s block: %v", b.Type, err)
					return nil // ignore err to continue parsing to next pem block
				}

				label = fmt.Sprintf("Certificate %v", cert.Subject)
				pub = cert.PublicKey
			case pemparser.PublicKeyPemType:
				pubi, err := x509.ParsePKIXPublicKey(b.Bytes)
				if err != nil {
					slog.Errorf("Failed to parse a %s block: %v", b.Type, err)
					return nil // ignore err to continue parsing to next pem block
				}

				var ok bool
				pub, ok = pubi.(crypto.PublicKey)
				if !ok {
					slog.Errorf("Unknown public key type: %v", reflect.TypeOf(pubi))
					return nil // ignore err to continue parsing to next pem block
				}
				label = fmt.Sprintf("PublicKey Type=%v", b.Type)
			}
		}
		if pub == nil {
			slog.Errorf("Could not extract a public key from block: Type: %q.", b.Type)
			return nil
		}

		hash, err := wcrypto.PubKeyPinString(pub)
		if err != nil {
			slog.Errorf("Failed to generate pubkeyhash: %v", err)
			return nil // ignore err to continue parsing other pem blocks
		}
		kh := KeyHash{Label: label, Hash: hash}

		for i, e := range khs {
			if kh.Hash == e.Hash {
				// overwrite label if Certificate label
				if strings.HasPrefix(kh.Label, "Certificate") {
					khs[i].Label = kh.Label
				}

				// continue parsing to next pem block
				return nil
			}
		}
		khs = append(khs, kh)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return khs, nil
}

var Command = &cli.Command{
	Name:    "pubkeyhash",
	Usage:   "Dump pubkeyhash of the specified public key/certificate",
	Aliases: []string{"hash"},
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:    "output",
			Aliases: []string{"o"},
			Usage:   "Output format. (full, hashonly)",
			Value:   "full",
		},
		&cli.PathFlag{
			Name:    "file",
			Aliases: []string{"f"},
			Usage:   "PEM file containing public key/certificates",
			Value:   "-",
		},
	},
	Action: func(c *cli.Context) error {
		env := action.GlobalEnvironment

		ftstr := c.String("output")
		ft, err := FormatTypeFromString(ftstr)
		if err != nil {
			return err
		}

		var r io.Reader

		path := c.String("file")
		if path == "-" {
			r = os.Stdin
		} else {
			f, err := os.Open(path)
			if err != nil {
				return err
			}
			defer f.Close()

			r = f
		}

		bs, err := ioutil.ReadAll(r)
		if err != nil {
			return err
		}

		khs, err := ExtractPublicKeyHashesFromPem(bs, env.Logger)
		if err != nil {
			return err
		}

		for _, e := range khs {
			if ft.ShouldOutputLabel() {
				fmt.Printf("# %s\n", e.Label)
			}
			fmt.Printf("%s\n", e.Hash)
		}

		return nil
	},
}
