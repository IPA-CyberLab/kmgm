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

	"github.com/urfave/cli/v2"

	action "github.com/IPA-CyberLab/kmgm/action"
	"github.com/IPA-CyberLab/kmgm/pemparser"
	"github.com/IPA-CyberLab/kmgm/wcrypto"
)

var Command = &cli.Command{
	Name:    "pubkeyhash",
	Usage:   "Dump pubkeyhash of the specified public key/certificate",
	Aliases: []string{"hash"},
	Flags: []cli.Flag{
		&cli.PathFlag{
			Name:    "file",
			Aliases: []string{"f"},
			Usage:   "PEM file containing public key/certificates",
			Value:   "-",
		},
	},
	Action: func(c *cli.Context) error {
		env := action.GlobalEnvironment
		slog := env.Logger.Sugar()

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
		err = pemparser.ForeachPemBlock(bs, func(b *pem.Block) error {
			var pub crypto.PublicKey

			// FIXME[P4]: support private key as well -> extract pubkey
			switch b.Type {
			case pemparser.CertificatePemType:
				cert, err := x509.ParseCertificate(b.Bytes)
				if err != nil {
					// FIXME[P4]: dump prefix?
					slog.Errorf("Failed to parse a %s block: %v", b.Type, err)
					return nil // ignore err to continue parsing other pem blocks
				}

				pub = cert.PublicKey
			case pemparser.PublicKeyPemType:
				pubi, err := x509.ParsePKIXPublicKey(b.Bytes)
				if err != nil {
					// FIXME[P4]: dump prefix?
					slog.Errorf("Failed to parse a %s block: %v", b.Type, err)
					return nil // ignore err to continue parsing other pem blocks
				}

				var ok bool
				pub, ok = pubi.(crypto.PublicKey)
				if !ok {
					slog.Errorf("Unknown public key type: %v", reflect.TypeOf(pubi))
					return nil // ignore err to continue parsing other pem blocks
				}
			}
			if pub == nil {
				return nil
			}

			hash, err := wcrypto.PubKeyPinString(pub)
			if err != nil {
				slog.Errorf("Failed to generate pubkeyhash: %v", err)
				return nil // ignore err to continue parsing other pem blocks
			}

			// FIXME[P2]: dump subject if cmdlineflag
			fmt.Printf("%s\n", hash)
			return nil
		})
		if err != nil {
			return err
		}

		return nil
	},
}
