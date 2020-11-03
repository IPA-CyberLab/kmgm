package consts

import (
	"encoding/asn1"
	"time"
)

const NodesOutOfSyncThreshold = 1 * time.Minute
const AuthProfileName = ".kmgm_server"
const PrometheusNamespace = "kmgm"

var (
	OIDExtensionKeyUsage         = asn1.ObjectIdentifier{2, 5, 29, 15}
	OIDExtensionExtendedKeyUsage = asn1.ObjectIdentifier{2, 5, 29, 37}
	OIDExtKeyUsageServerAuth     = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1}
	OIDExtKeyUsageClientAuth     = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 2}
)
