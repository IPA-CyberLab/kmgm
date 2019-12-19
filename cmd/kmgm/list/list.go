package list

import (
	"fmt"

	"github.com/urfave/cli/v2"

	wcli "github.com/IPA-CyberLab/kmgm/cli"
	"github.com/IPA-CyberLab/kmgm/pemparser"
	"github.com/IPA-CyberLab/kmgm/storage/issuedb"
)

// FIXME[PX]: [DB op] list all issued certs
// FIXME[PX]: [DB op] check that issued certs expires > threshold

const dateFormat = "06/01/02"

func certInfo(pem []byte) string {
	if len(pem) == 0 {
		return "PEM not found in DB entry"
	}

	certs, err := pemparser.ParseCertificates(pem)
	if err != nil {
		return fmt.Sprintf("error: Failed to parse PEM: %v", err)
	}
	if len(certs) != 1 {
		return fmt.Sprintf("error: %d certs found in PEM, expected only one.", len(certs))
	}

	c := certs[0]
	return fmt.Sprintf("%s %s %v",
		c.NotBefore.Format(dateFormat),
		c.NotAfter.Format(dateFormat),
		c.Subject)
}

// FIXME[P2]: --all-profiles
var Command = &cli.Command{
	Name:    "list",
	Usage:   "List certificates issued",
	Aliases: []string{"ls"},
	Action: func(c *cli.Context) error {
		env := wcli.GlobalEnvironment

		profile, err := env.Profile()
		if err != nil {
			return err
		}

		db, err := issuedb.New(env.Randr, profile.IssueDBPath())
		if err != nil {
			return err
		}

		es, err := db.Entries()
		if err != nil {
			return err
		}

		//                    1         2         3         4         5         6         7
		//          01234567890123456789012345678901234567890123456789012345678901234567890123456789
		//          01234567 0123456789012345678
		fmt.Printf("                             YY/MM/DD YY/MM/DD\n")
		fmt.Printf("Status   SerialNumber        NotBefor NotAfter Subject\n")
		for _, e := range es {
			infotxt := certInfo([]byte(e.CertificatePEM))

			switch e.State {
			case issuedb.IssueInProgress:
				fmt.Printf("issueing %19d\n", e.SerialNumber)

			case issuedb.ActiveCertificate:
				fmt.Printf("active   %19d %s\n", e.SerialNumber, infotxt)
			}
		}

		return nil
	},
}
