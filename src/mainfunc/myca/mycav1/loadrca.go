package mycav1

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"github.com/SongZihuan/MyCA/src/rootca"
	"github.com/SongZihuan/MyCA/src/utils"
	"os"
	"path"
)

func LoadRCA() (cert *x509.Certificate, key crypto.PrivateKey, fullchain []byte, rcaInfo *rootca.RCAInfo, err error) {
	c := showAllRCA()
	if len(c) == 0 {
		return nil, nil, nil, nil, fmt.Errorf("no RCA available")
	}

	fmt.Printf("Select an RCA and enter its serial number: ")
	i := ReadNumber() - 1 // 显示的列表是从1开始计数的

	if i < 0 || i >= len(c) {
		return nil, nil, nil, nil, fmt.Errorf("invalid serial number")
	}

	passwordFunc := func() string {
		fmt.Printf("Entery the password of the private key: ")
		return ReadPassword()
	}

	return loadRCA(c[i], passwordFunc)
}

func loadRCA(name string, passwordFunc func() string) (cert *x509.Certificate, key crypto.PrivateKey, fullchain []byte, rcaInfo *rootca.RCAInfo, err error) {
	certPEM, err := utils.ReadPemBlock(path.Join(home, "rca", name, "cert.pem"))
	if err != nil {
		return nil, nil, nil, nil, err
	} else if certPEM.Type != utils.PemTypeCertificate {
		return nil, nil, nil, nil, fmt.Errorf("pem type of cert error")
	}

	keyPEM, err := utils.ReadPemBlock(path.Join(home, "rca", name, "key.pem"))
	if err != nil {
		return nil, nil, nil, nil, err
	} else if keyPEM.Type != utils.PemTypePrivateKeyWithPassword && keyPEM.Type != utils.PemTypePrivateKeyNotPassword {
		return nil, nil, nil, nil, fmt.Errorf("pem type of key error")
	}

	fullchain, err = os.ReadFile(path.Join(home, "rca", name, "fullchain.pem"))
	if err != nil {
		return nil, nil, nil, nil, err
	}

	cert, err = x509.ParseCertificate(certPEM.Bytes)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	if keyPEM.Type == utils.PemTypePrivateKeyWithPassword {
		password := passwordFunc()
		key, _, err = utils.ParserPrivateKey(keyPEM.Bytes, password)
		if err != nil {
			return nil, nil, nil, nil, err
		}
	} else {
		key, _, err = utils.ParserPrivateKey(keyPEM.Bytes)
		if err != nil {
			return nil, nil, nil, nil, err
		}
	}

	rcaInfo, err = rootca.GetRCAInfo(path.Join(home, "rca", name, "rca-info.gob"))
	if err != nil {
		return nil, nil, nil, nil, err
	}

	return cert, key, fullchain, rcaInfo, nil
}
