package storage

import (
	"bytes"
	"encoding/base64"
	"text/template"
)

const secretTemplateSource = `
apiVersion: v1
kind: Secret
type: kubernetes.io/tls                                                                                                                                                                                                                                                                    │
metadata:
{{- if .Namespace }}
  namespace: {{ .Namespace }}
{{- end }}
  name: {{ .Name }}
data:
  ca.crt: {{ .CACertBase64 }}
  tls.crt: {{ .CertBase64 }}
  tls.key: {{ .KeyBase64 }}
`

var secretTemplate = template.Must(template.New("secret").Parse(secretTemplateSource))

// KubernetesSecretFromCertAndKey creates a k8s secret yaml from given cert and key.
func KubernetesSecretFromCertAndKey(name, namespace string, cacertPem, certPem, keyPem []byte) []byte {
	var buf bytes.Buffer

	if err := secretTemplate.Execute(&buf, map[string]interface{}{
		"Name":         name,
		"Namespace":    namespace,
		"CACertBase64": base64.StdEncoding.EncodeToString(cacertPem),
		"CertBase64":   base64.StdEncoding.EncodeToString(certPem),
		"KeyBase64":    base64.StdEncoding.EncodeToString(keyPem),
	}); err != nil {
		panic(err)
	}

	return buf.Bytes()
}
