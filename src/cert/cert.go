package cert

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
	"net"
	"net/url"
	"time"
)

// CreateCert 创建由CA签名的IP、域名证书
func CreateCert(cryptoType utils.CryptoType, keyLength int, org string, cn string, domains []string, ips []net.IP, emails []string, urls []*url.URL, notBefore time.Time, notAfter time.Time, caSerialNumber *utils.FileTack[*big.Int], ca *x509.Certificate, caKey crypto.PrivateKey) (*x509.Certificate, crypto.PrivateKey, error) {
	var privKey crypto.PrivateKey
	var pubKey interface{}

	if cn == "" {
		if len(domains) != 0 {
			cn = domains[0]
		} else if len(ips) != 0 {
			cn = ips[0].String()
		} else if len(emails) != 0 {
			cn = emails[0]
		} else if len(urls) != 0 {
			cn = urls[0].String()
		} else {
			cn = utils.RandStr(6 + utils.RandIntn(3)) // 6-8位随机字符串
		}
	}

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

	if notBefore.Equal(time.Time{}) {
		notBefore = time.Now()
	}

	if notAfter.Equal(time.Time{}) {
		notAfter = notBefore.Add(time.Hour * 24 * 365 * 5) // 5年
	}

	caSerialNumber.Value = new(big.Int).Add(caSerialNumber.Value, big.NewInt(1))

	template := &x509.Certificate{
		SerialNumber: caSerialNumber.Value,
		Subject: pkix.Name{
			Organization: []string{org},
			CommonName:   cn,
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageAny}, // 允许全部扩展用途
		BasicConstraintsValid: true,
		IsCA:                  false,
		DNSNames:              domains,
		IPAddresses:           ips,
		EmailAddresses:        emails,
		URIs:                  urls,
	}

	derBytes, err := x509.CreateCertificate(utils.Rander(), template, ca, pubKey, caKey)
	if err != nil {
		return nil, nil, err
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, nil, err
	}

	return cert, privKey, nil
}

// CreateSelfCert 创建自签名域名、IP证书
func CreateSelfCert(cryptoType utils.CryptoType, keyLength int, org string, cn string, domains []string, ips []net.IP, emails []string, urls []*url.URL, notBefore time.Time, notAfter time.Time) (*x509.Certificate, crypto.PrivateKey, error) {
	var privKey crypto.PrivateKey
	var pubKey interface{}

	if cn == "" {
		if len(domains) != 0 {
			cn = domains[0]
		} else if len(ips) != 0 {
			cn = ips[0].String()
		} else if len(emails) != 0 {
			cn = emails[0]
		} else if len(urls) != 0 {
			cn = urls[0].String()
		} else {
			cn = utils.RandStr(6 + utils.RandIntn(3)) // 6-8位随机字符串
		}
	}

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

	if notBefore.Equal(time.Time{}) {
		notBefore = time.Now()
	}

	if notAfter.Equal(time.Time{}) {
		notAfter = notBefore.Add(time.Hour * 24 * 365 * 5) // 5年
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{org},
			CommonName:   cn,
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageAny}, // 允许全部扩展用途
		BasicConstraintsValid: true,
		IsCA:                  false,
		DNSNames:              domains,
		IPAddresses:           ips,
		EmailAddresses:        emails,
		URIs:                  urls,
	}

	derBytes, err := x509.CreateCertificate(utils.Rander(), template, template, pubKey, privKey)
	if err != nil {
		return nil, nil, err
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, nil, err
	}

	return cert, privKey, nil
}
