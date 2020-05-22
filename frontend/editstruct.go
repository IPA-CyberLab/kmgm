package frontend

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"log"
	"strings"
	"text/template"

	"github.com/IPA-CyberLab/kmgm/keyusage"
	"gopkg.in/yaml.v2"
)

type templateContext struct {
	ErrorString string      `yaml:"-"`
	Config      interface{} `yaml:"config"`
}

const stripBeforeLine = "# *** LINES ABOVE WILL BE AUTOMATICALLY DELETED ***"

const configTemplateTextPrologue = `
{{- define "subject" -}}
  # The subject explains name, affiliation, and location of the target computer,
  # user, or service the cert is issued against.
  subject:
    commonName: {{ .CommonName }}
    organization: {{ .Organization }}
    organizationalUnit: {{ .OrganizationalUnit }}
    country: {{ .Country }}
    locality: {{ .Locality }}
    province: {{ .Province }}
    streetAddress: {{ .StreetAddress }}
    postalCode: {{ .PostalCode }}
{{- end -}}
{{- with .ErrorString -}}
# Please address the following error:
{{ PrependYamlCommentLiteral . -}}
{{ StripBeforeLine }}
{{- end }}
{{- with .Config -}}
`

const configTemplateTextEpilogue = `{{- end }}`

func PrependYamlCommentLiteral(s string) string {
	var b strings.Builder

	for {
		ss := strings.SplitN(s, "\n", 2)
		b.WriteString("#   ")
		b.WriteString(ss[0])
		b.WriteRune('\n')

		if len(ss) < 2 {
			break
		}
		s = ss[1]
	}
	return b.String()
}

func StripErrorText(s string) string {
	lines := strings.Split(s, "\n")

	for i, l := range lines {
		if l == stripBeforeLine {
			return strings.Join(lines[i+1:], "\n")
		}
	}
	return s
}

func CallVerifyMethod(cfgI interface{}) error {
	cfg := cfgI.(interface {
		Verify() error
	})
	if err := cfg.Verify(); err != nil {
		return err
	}
	return nil
}

func makeTemplate(tmplstr string) (*template.Template, error) {
	tmplstrFull := configTemplateTextPrologue + tmplstr + configTemplateTextEpilogue
	tmpl, err :=
		template.New("setupconfig").
			Funcs(template.FuncMap{
				"PrependYamlCommentLiteral": PrependYamlCommentLiteral,
				"StripBeforeLine":           func() string { return stripBeforeLine },
				"CommentOutIfFalse": func(e bool) string {
					if e {
						return ""
					}
					return "# "
				},
				"TestKeyUsageBit": func(bitName string, ku x509.KeyUsage) bool {
					bit, err := keyusage.BitNameToKeyUsage(bitName)
					if err != nil {
						panic(err)
					}

					return (ku & bit) != 0
				},
				"HasExtKeyUsage": func(ekuName string, ekus []x509.ExtKeyUsage) bool {
					// FIXME[P3]: move this logic to keyusage
					var eku x509.ExtKeyUsage
					switch ekuName {
					case "any":
						eku = x509.ExtKeyUsageAny
					case "clientAuth":
						eku = x509.ExtKeyUsageClientAuth
					case "serverAuth":
						eku = x509.ExtKeyUsageServerAuth
					default:
						log.Panicf("unknown ekuName %q", ekuName)
					}
					for _, e := range ekus {
						if e == eku {
							return true
						}
					}

					return false
				},
			}).
			Parse(tmplstrFull)
	if err != nil {
		return nil, err
	}

	return tmpl, nil
}

func DumpTemplate(tmplstr string, cfg interface{}) error {
	tmpl, err := makeTemplate(tmplstr)
	if err != nil {
		return err
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, templateContext{Config: cfg}); err != nil {
		return err
	}
	buf.WriteString(`
# noDefault prevents kmgm from assigning default values to unspecified fields.
# Setting "noDefault: true" is recommended for non-interactive invocations to
# avoid unintended behavior.
noDefault: true
`)

	if _, err := fmt.Print(buf.String()); err != nil {
		return err
	}
	return nil
}

func EditStructWithVerifier(fe Frontend, tmplstr string, cfg interface{}, VerifyCfg func(cfg interface{}) error) error {
	tmpl, err := makeTemplate(tmplstr)
	if err != nil {
		return err
	}

	tctx := templateContext{Config: cfg}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, tctx); err != nil {
		return err
	}
	cfgtxt := buf.String()

	VerifyText := func(src string) (string, error) {
		if err := yaml.UnmarshalStrict([]byte(src), tctx.Config); err != nil {
			// yaml error means that we can't use the template (we will lose the full data)
			txtwerr := strings.Join([]string{
				"# Please correct syntax error:\n",
				PrependYamlCommentLiteral(err.Error()),
				stripBeforeLine, "\n",
				StripErrorText(src)},
				"")
			return txtwerr, err
		}

		if err := VerifyCfg(tctx.Config); err != nil {
			tctx.ErrorString = err.Error()

			var buf bytes.Buffer
			if err := tmpl.Execute(&buf, tctx); err != nil {
				// FIXME[P3]: How should we handle template exec error?
				panic(err)
			}
			return buf.String(), err
		}

		return src, nil
	}

	if _, err := fe.EditText(cfgtxt, VerifyText); err != nil {
		return err
	}

	return nil
}
