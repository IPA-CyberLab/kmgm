package testkmgm

import (
	"crypto"
	"os"

	"github.com/IPA-CyberLab/kmgm/pemparser"
	"github.com/IPA-CyberLab/kmgm/wcrypto"
)

var rsa2048KeyIndex int = 0
var rsa4096KeyIndex int = 0
var ecKeyIndex int = 0

func ResetPreGenKeyIndex() {
	rsa2048KeyIndex = 0
	rsa4096KeyIndex = 0
	ecKeyIndex = 0
}

func GetPregenKeyPEM(ktype wcrypto.KeyType) []byte {
	switch ktype {
	case wcrypto.KeyRSA2048:
		pemstr := RSA2048Keys[rsa2048KeyIndex%len(RSA2048Keys)]
		rsa2048KeyIndex++
		return []byte(pemstr)
	case wcrypto.KeyRSA4096:
		pemstr := RSA4096Keys[rsa4096KeyIndex%len(RSA4096Keys)]
		rsa4096KeyIndex++
		return []byte(pemstr)
	case wcrypto.KeySECP256R1:
		pemstr := ECKeys[ecKeyIndex%len(ECKeys)]
		ecKeyIndex++
		return []byte(pemstr)
	default:
		panic("not available")
	}
}

func WritePregenKeyPEMToFile(ktype wcrypto.KeyType, path string) crypto.PrivateKey {
	pemData := GetPregenKeyPEM(ktype)
	pk, err := pemparser.ParsePrivateKey(pemData)
	if err != nil {
		panic(err)
	}
	if err := os.WriteFile(path, pemData, 0644); err != nil {
		panic(err)
	}
	return pk
}

func GetPregenKey(ktype wcrypto.KeyType) crypto.PrivateKey {
	pemData := GetPregenKeyPEM(ktype)
	pk, err := pemparser.ParsePrivateKey(pemData)
	if err != nil {
		panic(err)
	}
	return pk
}
