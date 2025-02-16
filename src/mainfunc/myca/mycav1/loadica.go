package mycav1

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"github.com/SongZihuan/MyCA/src/utils"
	"math/big"
	"os"
	"path"
)

func LoadICA() (cert *x509.Certificate, key crypto.PrivateKey, fullchain []byte, serialNumber *utils.FileTack[*big.Int], err error) {
	c := showAllICA()
	if len(c) == 0 {
		return nil, nil, nil, nil, fmt.Errorf("no ICA available")
	}

	fmt.Printf("Select an ICA and enter its serial number: ")
	i := ReadNumber() - 1 // 显示的列表是从1开始计数的

	if i < 0 || i >= len(c) {
		return nil, nil, nil, nil, fmt.Errorf("invalid serial number")
	}

	passwordFunc := func() string {
		fmt.Printf("Entery the password of the private key: ")
		return ReadPassword()
	}

	return loadICA(c[i], passwordFunc)
}

func loadICA(name string, passwordFunc func() string) (cert *x509.Certificate, key crypto.PrivateKey, fullchain []byte, serialNumber *utils.FileTack[*big.Int], err error) {
	certPEM, err := utils.ReadPemBlock(path.Join(home, "ica", name, "cert.pem"))
	if err != nil {
		return nil, nil, nil, nil, err
	} else if certPEM.Type != utils.PemTypeCertificate {
		return nil, nil, nil, nil, fmt.Errorf("pem type of cert error")
	}

	keyPEM, err := utils.ReadPemBlock(path.Join(home, "ica", name, "key.pem"))
	if err != nil {
		return nil, nil, nil, nil, err
	} else if keyPEM.Type != utils.PemTypePrivateKeyWithPassword && keyPEM.Type != utils.PemTypePrivateKeyNotPassword {
		return nil, nil, nil, nil, fmt.Errorf("pem type of key error")
	}

	fullchain, err = os.ReadFile(path.Join(home, "ica", name, "fullchain.pem"))
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

	serialNumber, err = utils.ReadBigIntFromFileWithFileStack(path.Join(home, "ica", name, "serial.num"))
	if err != nil {
		return nil, nil, nil, nil, err
	}

	return cert, key, fullchain, serialNumber, nil
}
