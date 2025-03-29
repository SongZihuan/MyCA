package rootca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/gob"
	"fmt"
	"github.com/SongZihuan/MyCA/src/sysinfo"
	"github.com/SongZihuan/MyCA/src/utils"
	"math/big"
	"os"
	"time"
)

type RCAInfo struct {
	SerialNumber          *big.Int
	OCSPServer            []string
	IssuingCertificateURL []string
	CRLDistributionPoints []string

	FilePath string `gob:"-"`
}

func init() {
	gob.Register(RCAInfo{})
}

func NewRCAInfo(filepath string, ocsp []string, issuerURL []string, crlURL []string) (*RCAInfo, error) {
	info := &RCAInfo{
		SerialNumber:          big.NewInt(0),
		OCSPServer:            ocsp,
		IssuingCertificateURL: issuerURL,
		CRLDistributionPoints: crlURL,
		FilePath:              filepath,
	}

	return info, nil
}

func GetRCAInfo(filepath string) (*RCAInfo, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = file.Close()
	}()

	var res RCAInfo
	decoder := gob.NewDecoder(file)
	err = decoder.Decode(&res)
	if err != nil {
		return nil, err
	}

	res.FilePath = filepath

	return &res, nil
}

func (info *RCAInfo) SaveRCAInfo() error {
	file, err := os.OpenFile(info.FilePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer func() {
		_ = file.Close()
	}()

	encoder := gob.NewEncoder(file)
	err = encoder.Encode(*info) // 不需要以指针形式出现
	if err != nil {
		return err
	}

	return nil
}

func (info *RCAInfo) NewCert() *big.Int {
	return info.SerialNumber.Add(info.SerialNumber, big.NewInt(1))
}

func (info *RCAInfo) GetIssuingCertificateURL() []string {
	return info.IssuingCertificateURL
}

func (info *RCAInfo) GetOCSPServer() []string {
	return info.OCSPServer
}

func (info *RCAInfo) GetCRLDistributionPoints() []string {
	return info.CRLDistributionPoints
}

// CreateRCA 创建根CA证书
func CreateRCA(infoFilePath string, cryptoType utils.CryptoType, keyLength int, org string, cn string, ocsp []string, selfURL []string, crlURL []string, notBefore time.Time, notAfter time.Time) (*x509.Certificate, crypto.PrivateKey, *RCAInfo, error) {
	var privKey crypto.PrivateKey
	var pubKey interface{}

	info, err := NewRCAInfo(infoFilePath, ocsp, selfURL, crlURL)
	if err != nil {
		return nil, nil, nil, err
	}

	switch cryptoType {
	case utils.CryptoTypeRsa:
		if keyLength != 2048 && keyLength != 4096 {
			return nil, nil, nil, fmt.Errorf("unsupported RSA key length: %d", keyLength)
		}

		priv, err := rsa.GenerateKey(utils.Rander(), keyLength)
		if err != nil {
			return nil, nil, nil, err
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
			return nil, nil, nil, fmt.Errorf("unsupported ECC key length: %d", keyLength)
		}
		priv, err := ecdsa.GenerateKey(curve, utils.Rander())
		if err != nil {
			return nil, nil, nil, err
		}
		privKey = priv
		pubKey = &priv.PublicKey
	default:
		return nil, nil, nil, fmt.Errorf("unsupported crypto type: %s", cryptoType)
	}

	org, cn = sysinfo.CreateCASubject(org, cn)

	if notBefore.Equal(time.Time{}) {
		notBefore = time.Now()
	}

	if notAfter.Equal(time.Time{}) {
		notAfter = notBefore.Add(time.Hour * 24 * 365 * 10) // 10年
	}

	template := &x509.Certificate{
		SerialNumber: info.NewCert(),
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

		OCSPServer:            info.OCSPServer,
		IssuingCertificateURL: info.IssuingCertificateURL,
		CRLDistributionPoints: info.CRLDistributionPoints,
	}

	derBytes, err := x509.CreateCertificate(utils.Rander(), template, template, pubKey, privKey)
	if err != nil {
		return nil, nil, nil, err
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, nil, nil, err
	}

	return cert, privKey, info, nil
}
