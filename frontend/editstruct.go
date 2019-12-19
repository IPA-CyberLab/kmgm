package frontend

import (
	"bytes"
	"net"
	"strings"
	"text/template"

	"gopkg.in/yaml.v2"
)

type templateContext struct {
	ErrorString string
	Config      interface{}
}

const stripBeforeLine = "# *** LINES ABOVE WILL BE AUTOMATICALLY DELETED ***"

const configTemplateTextPrologue = `
{{- with .ErrorString -}}
# Please address the following error:
{{ PrependYamlCommentLiteral . -}}
{{ StripBeforeLine }}
{{- end -}}
{{- with .Config -}}
`
const configTemplateTextEpilogue = "{{- end -}}"

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

func IsLoopback(ip net.IP) bool {
	return ip.IsLoopback()
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

func EditStructWithVerifier(fe Frontend, tmpl string, cfg interface{}, VerifyCfg func(cfg interface{}) error) error {
	tmpltxt := configTemplateTextPrologue + tmpl + configTemplateTextEpilogue
	configTemplate, err :=
		template.New("setupconfig").
			Funcs(template.FuncMap{
				"PrependYamlCommentLiteral": PrependYamlCommentLiteral,
				"IsLoopback":                IsLoopback,
				"StripBeforeLine":           func() string { return stripBeforeLine },
			}).
			Parse(tmpltxt)
	if err != nil {
		return err
	}

	tctx := templateContext{Config: cfg}

	var buf bytes.Buffer
	if err := configTemplate.Execute(&buf, tctx); err != nil {
		return err
	}

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
			if err := configTemplate.Execute(&buf, tctx); err != nil {
				// FIXME[P3]: How should we handle template exec error?
				panic(err)
			}
			return buf.String(), err
		}

		return src, nil
	}

	cfgtxt := buf.String()
	if _, err := fe.EditText(cfgtxt, VerifyText); err != nil {
		return err
	}

	return nil
}
