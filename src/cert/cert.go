package cert

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/gob"
	"fmt"
	"github.com/SongZihuan/MyCA/src/global"
	"github.com/SongZihuan/MyCA/src/utils"
	"math/big"
	"net"
	"net/url"
	"os"
	"time"
)

type CAInfo interface {
	NewCertSerialNumber() (*big.Int, error)
	GetIssuingCertificateURL() []string
	GetOCSPServer() []string
	GetCRLDistributionPoints() []string
}

type CertInfo struct {
	SerialNumber       *big.Int
	SelfCertificateURL []string
	CA                 CAInfo
	FilePath           string `gob:"-"`
}

func NewCertInfo(filepath string, ca CAInfo) (*CertInfo, error) {
	info := &CertInfo{
		SerialNumber: big.NewInt(0),
		FilePath:     filepath,
		CA:           ca,
	}

	return info, nil
}

func init() {
	gob.Register(CertInfo{})
}

func GetCertInfo(filepath string) (*CertInfo, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = file.Close()
	}()

	var res CertInfo
	decoder := gob.NewDecoder(file)
	err = decoder.Decode(&res)
	if err != nil {
		return nil, err
	}

	res.FilePath = filepath

	return &res, nil
}

func (info *CertInfo) SaveCertInfo() error {
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

func (info *CertInfo) GetSerialNumber() (*big.Int, error) {
	return info.CA.NewCertSerialNumber()
}

func (info *CertInfo) NewCert() *big.Int {
	panic("Not a CA!")
}

func (info *CertInfo) GetIssuingCertificateURL() []string {
	panic("Not a CA!")
}

// CreateCert 创建由CA签名的IP、域名证书
func CreateCert(infoFilePath string, caInfo CAInfo, cryptoType utils.CryptoType, keyLength int, subject *global.CertSubject, keyUsage x509.KeyUsage, extKeyUsage []x509.ExtKeyUsage, domains []string, ips []net.IP, emails []string, urls []*url.URL, notBefore time.Time, notAfter time.Time, ca *x509.Certificate, caKey crypto.PrivateKey) (*x509.Certificate, crypto.PrivateKey, *CertInfo, error) {
	var privKey crypto.PrivateKey
	var pubKey crypto.PublicKey

	info, err := NewCertInfo(infoFilePath, caInfo)
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

	serialNumber, err := info.GetSerialNumber()
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
		IsCA:                  false,

		DNSNames:       domains,
		IPAddresses:    ips,
		EmailAddresses: emails,
		URIs:           urls,

		SubjectKeyId:   []byte(ski),
		AuthorityKeyId: ca.SubjectKeyId,

		// 此处CA证书和终端证书不同，CA显示自己的吊销列表，终端证书显示对于CA的吊销列表
		OCSPServer:            info.CA.GetOCSPServer(),
		IssuingCertificateURL: info.CA.GetIssuingCertificateURL(),
		CRLDistributionPoints: info.CA.GetCRLDistributionPoints(),
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
