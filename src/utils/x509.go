package utils

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"github.com/youmark/pkcs8"
	"log"
	"os"
	"regexp"
	"software.sslmate.com/src/go-pkcs12"
	"strings"
)

type CryptoType string

const (
	CryptoTypeRsa   CryptoType = "RSA"
	CryptoTypeEcdsa CryptoType = "ECDSA"
	CryptoTypeEcc   CryptoType = "ECC"
)

const (
	PemTypePrivateKeyNotPassword  = "PRIVATE KEY"
	PemTypePrivateKeyWithPassword = "ENCRYPTED " + PemTypePrivateKeyNotPassword
	PemTypeCertificate            = "CERTIFICATE"
)

func SaveCertificate(cert *x509.Certificate, caFullchain []byte, cert1SavePath, cert2SavePath, fullchain1SavePath, fullchain2SavePath string) error {
	// 将证书转换为 PEM 格式
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  PemTypeCertificate,
		Bytes: cert.Raw,
	})

	fullchain := make([]byte, len(certPEM), len(certPEM)+len(caFullchain))
	copy(fullchain, certPEM)
	fullchain = append(fullchain, caFullchain...)

	// 写入文件
	err := os.WriteFile(cert1SavePath, certPEM, 0600)
	if err != nil {
		return err
	}

	err = os.WriteFile(cert2SavePath, certPEM, 0600)
	if err != nil {
		return err
	}

	err = os.WriteFile(fullchain1SavePath, fullchain, 0600)
	if err != nil {
		return err
	}

	err = os.WriteFile(fullchain2SavePath, fullchain, 0600)
	if err != nil {
		return err
	}

	return nil
}

func SavePrivateKey(key crypto.PrivateKey, pwStr string, savePath string) error {
	pwStr = strings.TrimSpace(pwStr)

	var password []byte = nil
	var pemType = PemTypePrivateKeyNotPassword
	if len(pwStr) != 0 {
		if !isValidPassword(pwStr) {
			return fmt.Errorf("password is invalid")
		}

		pemType = PemTypePrivateKeyWithPassword
		password = []byte(pwStr)
	}

	data, err := pkcs8.MarshalPrivateKey(key, password, pkcs8.DefaultOpts)
	if err != nil {
		return err
	}

	pemBlock := &pem.Block{
		Type:  pemType,
		Bytes: data,
	}

	err = os.WriteFile(savePath, pem.EncodeToMemory(pemBlock), 0600)
	if err != nil {
		return err
	}

	return nil
}

func SaveSPX(key crypto.PrivateKey, priPasswordStr string, cert *x509.Certificate, caFullchain []byte, savePath string) error {
	var priPassword []byte = nil
	var priType = PemTypePrivateKeyNotPassword
	priPasswordStr = strings.TrimSpace(priPasswordStr)

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  PemTypeCertificate,
		Bytes: cert.Raw,
	})

	if len(priPasswordStr) != 0 {
		if !isValidPassword(priPasswordStr) {
			return fmt.Errorf("password is invalid")
		}

		priType = PemTypePrivateKeyWithPassword
		priPassword = []byte(priPasswordStr)
	}

	priData, err := pkcs8.MarshalPrivateKey(key, priPassword, pkcs8.DefaultOpts)
	if err != nil {
		return err
	}

	priPEM := pem.EncodeToMemory(&pem.Block{
		Type:  priType,
		Bytes: priData,
	})

	spxData := make([]byte, len(certPEM), len(certPEM)+len(caFullchain))
	copy(spxData, certPEM)
	spxData = append(spxData, caFullchain...)
	spxData = append(spxData, priPEM...)

	err = os.WriteFile(savePath, spxData, 0600)
	if err != nil {
		return err
	}

	return nil
}

func SavePFX(key crypto.PrivateKey, priPasswordStr string, cert *x509.Certificate, caFullchain []byte, savePath string) error {
	priPasswordStr = strings.TrimSpace(priPasswordStr)

	if len(priPasswordStr) != 0 && !isValidPassword(priPasswordStr) {
		return fmt.Errorf("password is invalid")
	}

	var chainCerts = make([]*x509.Certificate, 0)
	for len(caFullchain) > 0 {
		var block *pem.Block
		block, caFullchain = pem.Decode(caFullchain)
		if block == nil {
			break
		} else if block.Type != "CERTIFICATE" {
			return fmt.Errorf("full chain block type error: %s", block.Type)
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return err
		}
		chainCerts = append(chainCerts, cert)
	}

	pfxData, err := pkcs12.LegacyRC2.WithRand(rand.Reader).Encode(key, cert, chainCerts, priPasswordStr)
	if err != nil {
		log.Fatalf("Failed to create PKCS #12 data: %v", err)
	}

	err = os.WriteFile(savePath, pfxData, 0600)
	if err != nil {
		return err
	}

	return nil
}

func ReadPemBlock(filePath string) (*pem.Block, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("not pem found")
	}

	return block, nil
}

func IsPrivateKeyPemBlockNeedPassword(block *pem.Block) bool {
	if block != nil && block.Type == PemTypePrivateKeyWithPassword {
		return true
	} else {
		return false
	}
}

func ParserPrivateKey(derData []byte, pwVargs ...string) (key crypto.PrivateKey, keyType CryptoType, err error) {
	if len(pwVargs) == 0 || strings.TrimSpace(pwVargs[0]) == "" {
		key, err = pkcs8.ParsePKCS8PrivateKey(derData)
	} else {
		password := []byte(strings.TrimSpace(pwVargs[0]))
		key, err = pkcs8.ParsePKCS8PrivateKey(derData, password)
	}
	if err != nil {
		return nil, "", err
	}

	switch key.(type) {
	case *rsa.PrivateKey:
		return key, CryptoTypeRsa, nil
	case *ecdsa.PrivateKey:
		return key, CryptoTypeEcdsa, nil
	default:
		return nil, "", fmt.Errorf("unknown crypto type")
	}
}

func isValidPassword(password string) bool {
	matched, _ := regexp.MatchString(`^[a-zA-Z0-9!@#$%^&*_]+$`, password)
	return matched
}

func CalculateSubjectKeyIdentifier(publicKey crypto.PublicKey) (string, error) {
	// 将公钥序列化为 PKIX 格式（DER 编码）
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", fmt.Errorf("failed to marshal public key: %w", err)
	}

	// 对公钥的 DER 编码计算 SHA-1 哈希值
	hash := sha1.Sum(publicKeyBytes)

	// 转换为十六进制字符串
	skiHex := hex.EncodeToString(hash[:])

	return skiHex, nil
}
