package ica

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/gob"
	"fmt"
	"github.com/SongZihuan/MyCA/src/global"
	"github.com/SongZihuan/MyCA/src/utils"
	"math/big"
	"os"
	"time"
)

type UpstreamCAInfo interface {
	GetIssuingCertificateURL() []string
}

type ICAInfo struct {
	SerialNumber          *big.Int
	OCSPServer            []string
	IssuingCertificateURL []string
	CRLDistributionPoints []string
	CA                    UpstreamCAInfo
	FilePath              string `gob:"-"`
}

func init() {
	gob.Register(ICAInfo{})
}

func NewICAInfo(filepath string, ca UpstreamCAInfo, ocsp []string, issuerURL []string, crlURL []string) (*ICAInfo, error) {
	randMax := new(big.Int).Lsh(big.NewInt(1), uint(40))
	randSerialNumber, err := rand.Int(rand.Reader, randMax)
	if err != nil {
		return nil, fmt.Errorf("error generating random number: %s", err.Error())
	}

	info := &ICAInfo{
		SerialNumber:          randSerialNumber,
		OCSPServer:            ocsp,
		IssuingCertificateURL: issuerURL,
		CRLDistributionPoints: crlURL,
		CA:                    ca,
		FilePath:              filepath,
	}

	return info, nil
}

func GetICAInfo(filepath string) (*ICAInfo, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = file.Close()
	}()

	var res ICAInfo
	decoder := gob.NewDecoder(file)
	err = decoder.Decode(&res)
	if err != nil {
		return nil, err
	}

	res.FilePath = filepath

	return &res, nil
}

func (info *ICAInfo) SaveICAInfo() error {
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

func (info *ICAInfo) NewCertSerialNumber() (*big.Int, error) {
	randMax := new(big.Int).Lsh(big.NewInt(1), uint(40))
	addSerialNumber, err := rand.Int(rand.Reader, randMax)
	if err != nil {
		return nil, fmt.Errorf("error generating random number: %s", err.Error())
	}

	return info.SerialNumber.Add(info.SerialNumber, addSerialNumber), nil
}

func (info *ICAInfo) GetIssuingCertificateURL() []string {
	return info.IssuingCertificateURL
}

func (info *ICAInfo) GetOCSPServer() []string {
	return info.OCSPServer
}

func (info *ICAInfo) GetCRLDistributionPoints() []string {
	return info.CRLDistributionPoints
}

// CreateICA 创建中间CA证书
func CreateICA(infoFilePath string, caInfo UpstreamCAInfo, cryptoType utils.CryptoType, keyLength int, subject *global.CertSubject, keyUsage x509.KeyUsage, extKeyUsage []x509.ExtKeyUsage, maxPathLen int, selfOSCP []string, selfURL []string, crlURL []string, notBefore time.Time, notAfter time.Time, ca *x509.Certificate, caKey crypto.PrivateKey) (*x509.Certificate, crypto.PrivateKey, *ICAInfo, error) {
	var privKey crypto.PrivateKey
	var pubKey crypto.PublicKey

	info, err := NewICAInfo(infoFilePath, caInfo, selfOSCP, selfURL, crlURL)
	if err != nil {
		return nil, nil, nil, err
	}

	err = subject.SetCNIfEmpty() // 兜底，确保CN被设置
	if err != nil {
		return nil, nil, nil, err
	}

	if extKeyUsage == nil {
		extKeyUsage = make([]x509.ExtKeyUsage, 0, 0)
	} else {
		extKeyUsage = utils.CopySlice(extKeyUsage)
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

	if notBefore.Equal(time.Time{}) {
		notBefore = time.Now()
	}

	if notAfter.Equal(time.Time{}) {
		notAfter = notBefore.Add(time.Hour * 24 * 365 * 5) // 5年
	}

	ski, err := utils.CalculateSubjectKeyIdentifier(pubKey)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("get subject key indentifier failed: %s", err.Error())
	}

	serialNumber, err := info.NewCertSerialNumber()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("get new serial number failed: %s", err.Error())
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      subject.ToPkixName(),
		NotBefore:    notBefore,
		NotAfter:     notAfter,

		KeyUsage:    keyUsage,
		ExtKeyUsage: extKeyUsage, // 允许全部扩展用途

		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            maxPathLen,
		MaxPathLenZero:        true,

		SubjectKeyId:   []byte(ski),
		AuthorityKeyId: ca.SubjectKeyId,

		// 此处CA证书和终端证书不同，CA显示自己的吊销列表，终端证书显示对于CA的吊销列表
		OCSPServer:            info.OCSPServer,
		IssuingCertificateURL: info.CA.GetIssuingCertificateURL(),
		CRLDistributionPoints: info.CRLDistributionPoints,
	}

	derBytes, err := x509.CreateCertificate(utils.Rander(), template, ca, pubKey, caKey)
	if err != nil {
		return nil, nil, nil, err
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, nil, nil, err
	}

	return cert, privKey, info, nil
}
