package ica

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"github.com/SongZihuan/MyCA/src/utils"
	"math/big"
	"time"
)

// CreateICA 创建中间CA证书
func CreateICA(cryptoType utils.CryptoType, keyLength int, org string, cn string, notBefore time.Time, notAfter time.Time, rootSerialNumber *utils.FileTack[*big.Int], rootCert *x509.Certificate, rootKey crypto.PrivateKey) (*x509.Certificate, crypto.PrivateKey, error) {
	var privKey crypto.PrivateKey
	var pubKey interface{}

	switch cryptoType {
	case utils.CryptoTypeRsa:
		if keyLength != 2048 && keyLength != 4096 {
			return nil, nil, fmt.Errorf("unsupported RSA key length: %d", keyLength)
		}

		priv, err := rsa.GenerateKey(utils.Rander(), keyLength)
		if err != nil {
			return nil, nil, err
		}

		privKey = priv
		pubKey = &priv.PublicKey
	case utils.CryptoTypeEcc:
		fallthrough
	case utils.CryptoTypeEcdsa:
		var curve elliptic.Curve
		switch keyLength {
		case 256:
			curve = elliptic.P256()
		case 384:
			curve = elliptic.P384()
		case 521:
			curve = elliptic.P521()
		default:
			return nil, nil, fmt.Errorf("unsupported ECC key length: %d", keyLength)
		}
		priv, err := ecdsa.GenerateKey(curve, utils.Rander())
		if err != nil {
			return nil, nil, err
		}
		privKey = priv
		pubKey = &priv.PublicKey
	default:
		return nil, nil, fmt.Errorf("unsupported crypto type: %s", cryptoType)
	}

	if org == "" {
		org = "MyOrg"
	}

	if cn == "" {
		cn = fmt.Sprintf("I%02d", utils.RandIntn(98)+1) // 数字范围1-99
	}

	if notBefore.Equal(time.Time{}) {
		notBefore = time.Now()
	}

	if notAfter.Equal(time.Time{}) {
		notAfter = notBefore.Add(time.Hour * 24 * 365 * 5) // 5年
	}

	rootSerialNumber.Value = new(big.Int).Add(rootSerialNumber.Value, big.NewInt(1))

	template := &x509.Certificate{
		SerialNumber: rootSerialNumber.Value,
		Subject: pkix.Name{
			Organization: []string{org},
			CommonName:   cn,
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageAny}, // 允许全部扩展用途
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            -1,
		MaxPathLenZero:        false,
	}

	derBytes, err := x509.CreateCertificate(utils.Rander(), template, rootCert, pubKey, rootKey)
	if err != nil {
		return nil, nil, err
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, nil, err
	}

	return cert, privKey, nil
}
