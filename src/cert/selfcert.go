// Copyright 2025 MyCA Authors. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package cert

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
	"net"
	"net/url"
	"os"
	"time"
)

type SelfCertInfo struct {
	OCSPServer            []string
	IssuingCertificateURL []string
	CRLDistributionPoints []string

	FilePath string `gob:"-"`
}

func init() {
	gob.Register(SelfCertInfo{})
}

func NewSelfCertInfo(filepath string, ocsp []string, issuerURL []string, crlURL []string) (*SelfCertInfo, error) {
	info := &SelfCertInfo{
		OCSPServer:            ocsp,
		IssuingCertificateURL: issuerURL,
		CRLDistributionPoints: crlURL,
		FilePath:              filepath,
	}

	return info, nil
}

func GetSelfCertInfo(filepath string) (*SelfCertInfo, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = file.Close()
	}()

	var res SelfCertInfo
	decoder := gob.NewDecoder(file)
	err = decoder.Decode(&res)
	if err != nil {
		return nil, err
	}

	res.FilePath = filepath

	return &res, nil
}

func (info *SelfCertInfo) SaveSelfCert() error {
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

func (info *SelfCertInfo) NewCertSerialNumber() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), uint(40)))
}

func (info *SelfCertInfo) GetIssuingCertificateURL() []string {
	return info.IssuingCertificateURL
}

func (info *SelfCertInfo) GetOCSPServer() []string {
	return info.OCSPServer
}

func (info *SelfCertInfo) GetCRLDistributionPoints() []string {
	return info.CRLDistributionPoints
}

// CreateSelfCert 创建自签名域名、IP证书
func CreateSelfCert(infoFilePath string, cryptoType utils.CryptoType, keyLength int, subject *global.CertSubject, keyUsage x509.KeyUsage, extKeyUsage []x509.ExtKeyUsage, domains []string, ips []net.IP, emails []string, urls []*url.URL, ocsp []string, selfURL []string, crlURL []string, notBefore time.Time, notAfter time.Time) (*x509.Certificate, crypto.PrivateKey, *SelfCertInfo, error) {
	var privKey crypto.PrivateKey
	var pubKey crypto.PublicKey

	info, err := NewSelfCertInfo(infoFilePath, ocsp, selfURL, crlURL)
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
		IsCA:                  false,

		DNSNames:       domains,
		IPAddresses:    ips,
		EmailAddresses: emails,
		URIs:           urls,

		SubjectKeyId:   []byte(ski),
		AuthorityKeyId: []byte(ski),

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
