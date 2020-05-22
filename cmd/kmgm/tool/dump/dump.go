package dump

import (
	"io"
	"io/ioutil"
	"os"

	"github.com/urfave/cli/v2"

	"github.com/IPA-CyberLab/kmgm/cmd/kmgm/show"
	"github.com/IPA-CyberLab/kmgm/pemparser"
)

var Command = &cli.Command{
	Name:      "dump",
	Usage:     "dump details of the input x509 certificate",
	UsageText: `kmgm tool dump`,
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:    "output",
			Aliases: []string{"o"},
			Usage:   "Output format. (full, pem)",
			Value:   "full",
		},
		&cli.StringFlag{
			Name:    "input",
			Aliases: []string{"i"},
			Usage:   "The certificate file.",
			Value:   "-",
		},
	},
	Action: func(c *cli.Context) error {
		ftstr := c.String("output")
		ft, err := show.FormatTypeFromString(ftstr)
		if err != nil {
			return err
		}

		var r io.Reader
		inpath := c.String("input")
		if inpath == "-" {
			r = os.Stdin
		} else {
			f, err := os.Open(inpath)
			if err != nil {
				return err
			}
			r = f
			defer f.Close()
		}

		bs, err := ioutil.ReadAll(r)
		if err != nil {
			return err
		}

		certs, err := pemparser.ParseCertificates(bs)
		if err != nil {
			return err
		}

		w := os.Stdout
		for _, cert := range certs {
			show.PrintCertInfo(w, cert, ft)
		}

		return nil
	},
}
