package mycav1

import (
	"fmt"
	"github.com/SongZihuan/MyCA/src/cert"
	"github.com/SongZihuan/MyCA/src/ica"
	"github.com/SongZihuan/MyCA/src/rootca"
	"github.com/SongZihuan/MyCA/src/utils"
	"math/big"
	"net"
	"os"
	"path"
	"time"
)

func ShowAllRCA() {
	showAllRCA()
}

func ShowAllICA() {
	showAllICA()
}

func CreateRCA() {
	fmt.Println(cryptoMenu)
	fmt.Printf(">>> ")

	var cryptoType utils.CryptoType
	var keyLength int

	switch ReadNumber() {
	case 1:
		cryptoType = utils.CryptoTypeRsa
		keyLength = 2048
	case 2:
		cryptoType = utils.CryptoTypeRsa
		keyLength = 4096
	case 0:
		fallthrough
	default:
		fmt.Println("Warn: Use Default")
		fallthrough
	case 3:
		cryptoType = utils.CryptoTypeEcdsa
		keyLength = 256
	case 4:
		cryptoType = utils.CryptoTypeEcdsa
		keyLength = 384
	case 5:
		cryptoType = utils.CryptoTypeEcdsa
		keyLength = 521
	}

	fmt.Println("Crypto: ", cryptoType, keyLength)

	fmt.Printf("Org: ")
	org := ReadString()

	fmt.Printf("Common Name: ")
	cn := ReadString()

	fmt.Printf("Validity: ")
	validity := ReadTimeDuration(time.Hour * 24 * 365 * 10)

	notBefore := time.Now()
	notAfter := notBefore.Add(validity)

	caCert, key, err := rootca.CreateRCA(cryptoType, keyLength, org, cn, notBefore, notAfter)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	dirPath := path.Join(home, "rca", fmt.Sprintf("%s-%s", caCert.Subject.Organization[0], caCert.Subject.CommonName))
	cert1Path := path.Join(dirPath, "cert.pem")
	cert2Path := path.Join(dirPath, "cert.cer")
	fullchain1Path := path.Join(dirPath, "fullchain.pem")
	fullchain2Path := path.Join(dirPath, "fullchain.cer")
	serialNumberPath := path.Join(dirPath, "serial.num")
	keyPath := path.Join(dirPath, "key.pem")

	if utils.IsExists(cert1Path) || utils.IsExists(cert2Path) || utils.IsExists(fullchain1Path) || utils.IsExists(fullchain2Path) || utils.IsExists(keyPath) {
		fmt.Printf("There is a duplicate file, it will be overwritten. Do you confirm to save the certificate? [yes/no] ")
		if !ReadYesMust() {
			return
		}
	} else {
		fmt.Printf("Do you confirm to save the certificate? [yes/no] ")
		if !ReadYes() {
			return
		}
	}

	fmt.Printf("Set a password for private key: ")
	password := ReadPassword()

	err = os.MkdirAll(dirPath, 0600)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	err = utils.SaveCertificate(caCert, []byte{}, cert1Path, cert2Path, fullchain1Path, fullchain2Path)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	err = utils.SavePrivateKey(key, password, keyPath)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	err = utils.WriteBigIntToFile(serialNumberPath, big.NewInt(0))
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	fmt.Println("Success, save directory: ", dirPath)
}

func CreateICAFromRCA() {
	rcaCert, rcaKey, rcaFullchain, rcaSerialNumber, err := LoadRCA()
	if err != nil {
		fmt.Println("Error:", err.Error())
		return
	}

	fmt.Println(cryptoMenu)
	fmt.Printf(">>> ")

	var cryptoType utils.CryptoType
	var keyLength int

	switch ReadNumber() {
	case 1:
		cryptoType = utils.CryptoTypeRsa
		keyLength = 2048
	case 2:
		cryptoType = utils.CryptoTypeRsa
		keyLength = 4096
	case 0:
		fallthrough
	default:
		fmt.Println("Warn: Use Default")
		fallthrough
	case 3:
		cryptoType = utils.CryptoTypeEcdsa
		keyLength = 256
	case 4:
		cryptoType = utils.CryptoTypeEcdsa
		keyLength = 384
	case 5:
		cryptoType = utils.CryptoTypeEcdsa
		keyLength = 521
	}

	fmt.Println("Crypto: ", cryptoType, keyLength)

	fmt.Printf("Org: ")
	org := ReadString()

	fmt.Printf("Common Name: ")
	cn := ReadString()

	fmt.Printf("Validity: ")
	validity := ReadTimeDuration(time.Hour * 24 * 365 * 5)

	notBefore := time.Now()
	notAfter := notBefore.Add(validity)

	caCert, key, err := ica.CreateICA(cryptoType, keyLength, org, cn, notBefore, notAfter, rcaSerialNumber, rcaCert, rcaKey)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	dirPath := path.Join(home, "ica", fmt.Sprintf("%s-%s", caCert.Subject.Organization[0], caCert.Subject.CommonName))
	cert1Path := path.Join(dirPath, "cert.pem")
	cert2Path := path.Join(dirPath, "cert.cer")
	fullchain1Path := path.Join(dirPath, "fullchain.pem")
	fullchain2Path := path.Join(dirPath, "fullchain.cer")
	serialNumberPath := path.Join(dirPath, "serial.num")
	keyPath := path.Join(dirPath, "key.pem")

	if utils.IsExists(cert1Path) || utils.IsExists(cert2Path) || utils.IsExists(fullchain1Path) || utils.IsExists(fullchain2Path) || utils.IsExists(keyPath) {
		fmt.Printf("There is a duplicate file, it will be overwritten. Do you confirm to save the certificate? [yes/no] ")
		if !ReadYesMust() {
			return
		}
	} else {
		fmt.Printf("Do you confirm to save the certificate? [yes/no] ")
		if !ReadYes() {
			return
		}
	}

	fmt.Printf("Set a password for private key: ")
	password := ReadPassword()

	err = os.MkdirAll(dirPath, 0600)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	err = utils.SaveCertificate(caCert, rcaFullchain, cert1Path, cert2Path, fullchain1Path, fullchain2Path)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	err = utils.SavePrivateKey(key, password, keyPath)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	err = utils.WriteBigIntToFile(serialNumberPath, big.NewInt(0))
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	err = rcaSerialNumber.Save()
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	fmt.Println("Success, save directory: ", dirPath)
}

func CreateICAFromICA() {
	icaCert, icaKey, icaFullchain, icaSerialNumber, err := LoadICA()
	if err != nil {
		fmt.Println("Error:", err.Error())
		return
	}

	fmt.Println(cryptoMenu)
	fmt.Printf(">>> ")

	var cryptoType utils.CryptoType
	var keyLength int

	switch ReadNumber() {
	case 1:
		cryptoType = utils.CryptoTypeRsa
		keyLength = 2048
	case 2:
		cryptoType = utils.CryptoTypeRsa
		keyLength = 4096
	case 0:
		fallthrough
	default:
		fmt.Println("Warn: Use Default")
		fallthrough
	case 3:
		cryptoType = utils.CryptoTypeEcdsa
		keyLength = 256
	case 4:
		cryptoType = utils.CryptoTypeEcdsa
		keyLength = 384
	case 5:
		cryptoType = utils.CryptoTypeEcdsa
		keyLength = 521
	}

	fmt.Println("Crypto: ", cryptoType, keyLength)

	fmt.Printf("Org: ")
	org := ReadString()

	fmt.Printf("Common Name: ")
	cn := ReadString()

	fmt.Printf("Validity: ")
	validity := ReadTimeDuration(time.Hour * 24 * 365 * 5)

	notBefore := time.Now()
	notAfter := notBefore.Add(validity)

	caCert, key, err := ica.CreateICA(cryptoType, keyLength, org, cn, notBefore, notAfter, icaSerialNumber, icaCert, icaKey)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	dirPath := path.Join(home, "ica", fmt.Sprintf("%s-%s", caCert.Subject.Organization[0], caCert.Subject.CommonName))
	cert1Path := path.Join(dirPath, "cert.pem")
	cert2Path := path.Join(dirPath, "cert.cer")
	fullchain1Path := path.Join(dirPath, "fullchain.pem")
	fullchain2Path := path.Join(dirPath, "fullchain.cer")
	serialNumberPath := path.Join(dirPath, "serial.num")
	keyPath := path.Join(dirPath, "key.pem")

	if utils.IsExists(cert1Path) || utils.IsExists(cert2Path) || utils.IsExists(fullchain1Path) || utils.IsExists(fullchain2Path) || utils.IsExists(keyPath) {
		fmt.Printf("There is a duplicate file, it will be overwritten. Do you confirm to save the certificate? [yes/no] ")
		if !ReadYesMust() {
			return
		}
	} else {
		fmt.Printf("Do you confirm to save the certificate? [yes/no] ")
		if !ReadYes() {
			return
		}
	}

	fmt.Printf("Set a password for private key: ")
	password := ReadPassword()

	err = os.MkdirAll(dirPath, 0600)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	err = utils.SaveCertificate(caCert, icaFullchain, cert1Path, cert2Path, fullchain1Path, fullchain2Path)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	err = utils.SavePrivateKey(key, password, keyPath)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	err = utils.WriteBigIntToFile(serialNumberPath, big.NewInt(0))
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	err = icaSerialNumber.Save()
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	fmt.Println("Success, save directory: ", dirPath)
}

func CreateUserCertFromRCA() {
	rcaCert, rcaKey, rcaFullchain, rcaSerialNumber, err := LoadRCA()
	if err != nil {
		fmt.Println("Error:", err.Error())
		return
	}

	fmt.Println(cryptoMenu)
	fmt.Printf(">>> ")

	var cryptoType utils.CryptoType
	var keyLength int

	switch ReadNumber() {
	case 1:
		cryptoType = utils.CryptoTypeRsa
		keyLength = 2048
	case 2:
		cryptoType = utils.CryptoTypeRsa
		keyLength = 4096
	case 0:
		fallthrough
	default:
		fmt.Println("Warn: Use Default")
		fallthrough
	case 3:
		cryptoType = utils.CryptoTypeEcdsa
		keyLength = 256
	case 4:
		cryptoType = utils.CryptoTypeEcdsa
		keyLength = 384
	case 5:
		cryptoType = utils.CryptoTypeEcdsa
		keyLength = 521
	}

	fmt.Println("Crypto: ", cryptoType, keyLength)

	fmt.Printf("Org: ")
	org := ReadString()

	fmt.Printf("Validity: ")
	validity := ReadTimeDuration(time.Hour * 24 * 365 * 5)

	notBefore := time.Now()
	notAfter := notBefore.Add(validity)

	domains := make([]string, 0, 10)
	for {
		fmt.Printf("Enter your domain [empty to stop]: ")
		res := ReadString()
		if res == "" {
			break
		} else {
			domains = append(domains, res)
		}
	}

	ips := make([]net.IP, 0, 10)
	for {
		fmt.Printf("Enter your ip [empty to stop]: ")
		res := ReadString()
		if res == "" {
			break
		} else {
			ip := net.ParseIP(res)
			if ip == nil {
				fmt.Println("Error: not a valid ip")
			}

			ips = append(ips, ip)
		}
	}

	userCert, key, err := cert.CreateCert(cryptoType, keyLength, org, domains, ips, notBefore, notAfter, rcaSerialNumber, rcaCert, rcaKey)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	dirPath := path.Join(home, "cert", fmt.Sprintf("%s-%s-%s-%s", userCert.Subject.Organization[0], rcaCert.Subject.CommonName, userCert.Subject.CommonName, userCert.NotBefore.Format("2006-01-02-15-04-05")))
	cert1Path := path.Join(dirPath, "cert.pem")
	cert2Path := path.Join(dirPath, "cert.cer")
	fullchain1Path := path.Join(dirPath, "fullchain.pem")
	fullchain2Path := path.Join(dirPath, "fullchain.cer")
	keyPath := path.Join(dirPath, "key.pem")

	if utils.IsExists(cert1Path) || utils.IsExists(cert2Path) || utils.IsExists(fullchain1Path) || utils.IsExists(fullchain2Path) || utils.IsExists(keyPath) {
		fmt.Printf("There is a duplicate file, it will be overwritten. Do you confirm to save the certificate? [yes/no] ")
		if !ReadYesMust() {
			return
		}
	} else {
		fmt.Printf("Do you confirm to save the certificate? [yes/no] ")
		if !ReadYes() {
			return
		}
	}

	fmt.Printf("Set a password for private key: ")
	password := ReadPassword()

	err = os.MkdirAll(dirPath, 0600)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	err = utils.SaveCertificate(userCert, rcaFullchain, cert1Path, cert2Path, fullchain1Path, fullchain2Path)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	err = utils.SavePrivateKey(key, password, keyPath)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	err = rcaSerialNumber.Save()
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	fmt.Println("Success, save directory: ", dirPath)
}

func CreateUserCertFromICA() {
	icaCert, icaKey, icaFullchain, icaSerialNumber, err := LoadICA()
	if err != nil {
		fmt.Println("Error:", err.Error())
		return
	}

	fmt.Println(cryptoMenu)
	fmt.Printf(">>> ")

	var cryptoType utils.CryptoType
	var keyLength int

	switch ReadNumber() {
	case 1:
		cryptoType = utils.CryptoTypeRsa
		keyLength = 2048
	case 2:
		cryptoType = utils.CryptoTypeRsa
		keyLength = 4096
	case 0:
		fallthrough
	default:
		fmt.Println("Warn: Use Default")
		fallthrough
	case 3:
		cryptoType = utils.CryptoTypeEcdsa
		keyLength = 256
	case 4:
		cryptoType = utils.CryptoTypeEcdsa
		keyLength = 384
	case 5:
		cryptoType = utils.CryptoTypeEcdsa
		keyLength = 521
	}

	fmt.Println("Crypto: ", cryptoType, keyLength)

	fmt.Printf("Org: ")
	org := ReadString()

	fmt.Printf("Validity: ")
	validity := ReadTimeDuration(time.Hour * 24 * 365 * 5)

	notBefore := time.Now()
	notAfter := notBefore.Add(validity)

	domains := make([]string, 0, 10)
	for {
		fmt.Printf("Enter your domain [empty to stop]: ")
		res := ReadString()
		if res == "" {
			break
		} else {
			domains = append(domains, res)
		}
	}

	ips := make([]net.IP, 0, 10)
	for {
		fmt.Printf("Enter your ip [empty to stop]: ")
		res := ReadString()
		if res == "" {
			break
		} else {
			ip := net.ParseIP(res)
			if ip == nil {
				fmt.Println("Error: not a valid ip")
			}

			ips = append(ips, ip)
		}
	}

	userCert, key, err := cert.CreateCert(cryptoType, keyLength, org, domains, ips, notBefore, notAfter, icaSerialNumber, icaCert, icaKey)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	dirPath := path.Join(home, "cert", fmt.Sprintf("%s-%s-%s-%s", userCert.Subject.Organization[0], icaCert.Subject.CommonName, userCert.Subject.CommonName, userCert.NotBefore.Format("2006-01-02-15-04-05")))
	cert1Path := path.Join(dirPath, "cert.pem")
	cert2Path := path.Join(dirPath, "cert.cer")
	fullchain1Path := path.Join(dirPath, "fullchain.pem")
	fullchain2Path := path.Join(dirPath, "fullchain.cer")
	keyPath := path.Join(dirPath, "key.pem")

	if utils.IsExists(cert1Path) || utils.IsExists(cert2Path) || utils.IsExists(fullchain1Path) || utils.IsExists(fullchain2Path) || utils.IsExists(keyPath) {
		fmt.Printf("There is a duplicate file, it will be overwritten. Do you confirm to save the certificate? [yes/no] ")
		if !ReadYesMust() {
			return
		}
	} else {
		fmt.Printf("Do you confirm to save the certificate? [yes/no] ")
		if !ReadYes() {
			return
		}
	}

	fmt.Printf("Set a password for private key: ")
	password := ReadPassword()

	err = os.MkdirAll(dirPath, 0600)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	err = utils.SaveCertificate(userCert, icaFullchain, cert1Path, cert2Path, fullchain1Path, fullchain2Path)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	err = utils.SavePrivateKey(key, password, keyPath)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	err = icaSerialNumber.Save()
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	fmt.Println("Success, save directory: ", dirPath)
}

func CreateUserCertSelf() {
	fmt.Println(cryptoMenu)
	fmt.Printf(">>> ")

	var cryptoType utils.CryptoType
	var keyLength int

	switch ReadNumber() {
	case 1:
		cryptoType = utils.CryptoTypeRsa
		keyLength = 2048
	case 2:
		cryptoType = utils.CryptoTypeRsa
		keyLength = 4096
	case 0:
		fallthrough
	default:
		fmt.Println("Warn: Use Default")
		fallthrough
	case 3:
		cryptoType = utils.CryptoTypeEcdsa
		keyLength = 256
	case 4:
		cryptoType = utils.CryptoTypeEcdsa
		keyLength = 384
	case 5:
		cryptoType = utils.CryptoTypeEcdsa
		keyLength = 521
	}

	fmt.Println("Crypto: ", cryptoType, keyLength)

	fmt.Printf("Org: ")
	org := ReadString()

	fmt.Printf("Validity: ")
	validity := ReadTimeDuration(time.Hour * 24 * 365 * 5)

	notBefore := time.Now()
	notAfter := notBefore.Add(validity)

	domains := make([]string, 0, 10)
	for {
		fmt.Printf("Enter your domain [empty to stop]: ")
		res := ReadString()
		if res == "" {
			break
		} else {
			domains = append(domains, res)
		}
	}

	ips := make([]net.IP, 0, 10)
	for {
		fmt.Printf("Enter your ip [empty to stop]: ")
		res := ReadString()
		if res == "" {
			break
		} else {
			ip := net.ParseIP(res)
			if ip == nil {
				fmt.Println("Error: not a valid ip")
			}

			ips = append(ips, ip)
		}
	}

	userCert, key, err := cert.CreateSelfCert(cryptoType, keyLength, org, domains, ips, notBefore, notAfter)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	dirPath := path.Join(home, "cert", fmt.Sprintf("Self-%s-%s-%s-%s", userCert.Subject.Organization[0], userCert.Subject.CommonName, userCert.Subject.CommonName, userCert.NotBefore.Format("2006-01-02-15-04-05")))
	cert1Path := path.Join(dirPath, "cert.pem")
	cert2Path := path.Join(dirPath, "cert.cer")
	fullchain1Path := path.Join(dirPath, "fullchain.pem")
	fullchain2Path := path.Join(dirPath, "fullchain.cer")
	keyPath := path.Join(dirPath, "key.pem")

	if utils.IsExists(cert1Path) || utils.IsExists(cert2Path) || utils.IsExists(fullchain1Path) || utils.IsExists(fullchain2Path) || utils.IsExists(keyPath) {
		fmt.Printf("There is a duplicate file, it will be overwritten. Do you confirm to save the certificate? [yes/no] ")
		if !ReadYesMust() {
			return
		}
	} else {
		fmt.Printf("Do you confirm to save the certificate? [yes/no] ")
		if !ReadYes() {
			return
		}
	}

	fmt.Printf("Set a password for private key: ")
	password := ReadPassword()

	err = os.MkdirAll(dirPath, 0600)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	err = utils.SaveCertificate(userCert, []byte{}, cert1Path, cert2Path, fullchain1Path, fullchain2Path)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	err = utils.SavePrivateKey(key, password, keyPath)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	fmt.Println("Success, save directory: ", dirPath)
}
