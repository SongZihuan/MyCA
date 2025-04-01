package mycav1

import (
	"fmt"
	"github.com/SongZihuan/MyCA/src/cert"
	"github.com/SongZihuan/MyCA/src/ica"
	"github.com/SongZihuan/MyCA/src/rootca"
	"github.com/SongZihuan/MyCA/src/utils"
	"net"
	"net/mail"
	"net/url"
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

	subject, err := ReadSubject()
	if err != nil {
		fmt.Printf("Error: %s\n", err.Error())
		return
	}

	fmt.Printf("Validity: ")
	validity := ReadTimeDuration(time.Hour * 24 * 365 * 10)

	notBefore := time.Now()
	notAfter := notBefore.Add(validity)

	keyUsage, err := ReadKeyUsage("rca")
	if err != nil {
		fmt.Printf("Error: %s\n", err.Error())
		return
	}

	extKeyUsage, err := ReadExtKeyUsage()
	if err != nil {
		fmt.Printf("Error: %s\n", err.Error())
		return
	}

	fmt.Printf("Set the ca max path len limit [-1 means no limit]: ")
	maxPathLen := ReadNumber()
	if maxPathLen < -1 {
		maxPathLen = -1
		fmt.Printf("OK, the CA has not limit to create ica.\n")
	} else if maxPathLen == 0 {
		fmt.Printf("OK, the CA can not to create ica.\n")
	} else {
		fmt.Printf("OK, CA can create %d layers of ica.\n", maxPathLen)
	}

	ocspURLs := make([]string, 0, 10)
	for {
		fmt.Printf("Enter your OCSP Server URL [empty to stop]: ")
		res := ReadString()
		if res == "" {
			break
		} else {
			u, err := url.Parse(res)
			if err != nil {
				fmt.Printf("Error: not a valid URL (%s)\n", err.Error())
				break
			} else if u.Scheme != "http" && u.Scheme != "https" {
				fmt.Println("Error: not a valid HTTP/HTTPS URL")
				break
			}

			ocspURLs = append(ocspURLs, u.String())
		}
	}

	issurURLs := make([]string, 0, 10)
	for {
		fmt.Printf("Enter your Issuing Certificate URL [empty to stop]: ")
		res := ReadString()
		if res == "" {
			break
		} else {
			u, err := url.Parse(res)
			if err != nil {
				fmt.Printf("Error: not a valid URL (%s)\n", err.Error())
				break
			} else if u.Scheme != "http" && u.Scheme != "https" {
				fmt.Println("Error: not a valid HTTP/HTTPS URL")
				break
			}

			issurURLs = append(issurURLs, u.String())
		}
	}

	crlURLs := make([]string, 0, 10)
	for {
		fmt.Printf("Enter your CRL Distribution Points (URL) [empty to stop]: ")
		res := ReadString()
		if res == "" {
			break
		} else {
			u, err := url.Parse(res)
			if err != nil {
				fmt.Printf("Error: not a valid URL (%s)\n", err.Error())
				break
			} else if u.Scheme != "http" && u.Scheme != "https" {
				fmt.Println("Error: not a valid HTTP/HTTPS URL")
				break
			}

			crlURLs = append(crlURLs, u.String())
		}
	}

	fmt.Printf("Set a password for private key [empty is no password]: ")
	password := ReadPassword()

	err = subject.SetCNIfEmpty()
	if err != nil {
		fmt.Printf("Error: %s\n", err)
		return
	}

	_, dirPath, err := ReadDir(homeRCA, "RCA-", subject)
	if err != nil {
		fmt.Printf("Error: %s", err.Error())
		return
	}

	infoPath := path.Join(dirPath, "rca-info.gob")
	cert1Path := path.Join(dirPath, "cert.pem")
	cert2Path := path.Join(dirPath, "cert.cer")
	fullchain1Path := path.Join(dirPath, "fullchain.pem")
	fullchain2Path := path.Join(dirPath, "fullchain.cer")
	keyPath := path.Join(dirPath, "key.pem")
	spxPath := path.Join(dirPath, "cert.spx")
	pfxPath := path.Join(dirPath, "cert.pfx")

	if utils.IsExists(dirPath) {
		fmt.Printf("There is a duplicate file, it will be overwritten. Do you confirm to save the certificate?")
		if !ReadBoolDefaultNoPrint() {
			return
		}
	} else {
		fmt.Printf("Do you confirm to save the certificate?")
		if !ReadBoolDefaultYesPrint() {
			return
		}
	}

	err = os.MkdirAll(dirPath, 0600)
	if err != nil {
		fmt.Printf("Error: %s\n", err.Error())
		return
	}

	caCert, key, rcaInfo, err := rootca.CreateRCA(infoPath, cryptoType, keyLength, subject, keyUsage, extKeyUsage, maxPathLen, ocspURLs, issurURLs, crlURLs, notBefore, notAfter)
	if err != nil {
		fmt.Printf("Error: %s\n", err.Error())
		return
	}

	err = rcaInfo.SaveRCAInfo()
	if err != nil {
		fmt.Printf("Error: %s\n", err.Error())
		return
	}

	err = utils.SaveCertificate(caCert, []byte{}, cert1Path, cert2Path, fullchain1Path, fullchain2Path)
	if err != nil {
		fmt.Printf("Error: %s\n", err.Error())
		return
	}

	err = utils.SavePrivateKey(key, password, keyPath)
	if err != nil {
		fmt.Printf("Error: %s\n", err.Error())
		return
	}

	err = utils.SaveSPX(key, password, caCert, []byte{}, spxPath)
	if err != nil {
		fmt.Printf("Error: %s\n", err.Error())
		return
	}

	err = utils.SavePFX(key, password, caCert, []byte{}, pfxPath)
	if err != nil {
		fmt.Printf("Error: %s\n", err.Error())
		return
	}

	fmt.Println("Success, save directory: ", dirPath)
}

func CreateICAFromRCA() {
	rcaCert, rcaKey, rcaFullchain, rcaInfo, err := LoadRCA()
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

	subject, err := ReadSubject()
	if err != nil {
		fmt.Printf("Error: %s\n", err.Error())
		return
	}

	fmt.Printf("Validity: ")
	validity := ReadTimeDuration(time.Hour * 24 * 365 * 5)

	notBefore := time.Now()
	notAfter := notBefore.Add(validity)

	keyUsage, err := ReadKeyUsage("ica")
	if err != nil {
		fmt.Printf("Error: %s\n", err.Error())
		return
	}

	extKeyUsage, err := ReadExtKeyUsage()
	if err != nil {
		fmt.Printf("Error: %s\n", err.Error())
		return
	}

	fmt.Printf("Set the ca max path len limit [-1 means no limit]: ")
	maxPathLen := ReadNumber()
	if maxPathLen < -1 {
		if rcaCert.MaxPathLen != -1 {
			fmt.Printf("Error: bad max path len: path len must less than father ca")
			return
		}

		maxPathLen = -1
		fmt.Printf("OK, the CA has not limit to create ica.\n")
	} else if maxPathLen == 0 {
		if rcaCert.MaxPathLen == 0 {
			fmt.Printf("Error: bad max path len: path len must less than father ca")
			return
		}
		fmt.Printf("OK, the CA can not to create ica.\n")
	} else {
		if rcaCert.MaxPathLen != -1 && rcaCert.MaxPathLen < maxPathLen {
			fmt.Printf("Error: bad max path len: path len must less than father ca")
			return
		}
		fmt.Printf("OK, CA can create %d layers of ica.\n", maxPathLen)
	}

	selfOcspURLs := make([]string, 0, 10)
	for {
		fmt.Printf("Enter your OCSP Server URL [empty to stop]: ")
		res := ReadString()
		if res == "" {
			break
		} else {
			u, err := url.Parse(res)
			if err != nil {
				fmt.Printf("Error: not a valid URL (%s)\n", err.Error())
				break
			} else if u.Scheme != "http" && u.Scheme != "https" {
				fmt.Println("Error: not a valid HTTP/HTTPS URL")
				break
			}

			selfOcspURLs = append(selfOcspURLs, u.String())
		}
	}

	selfIssurURLs := make([]string, 0, 10)
	for {
		fmt.Printf("Enter your Issuing Certificate URL [empty to stop]: ")
		res := ReadString()
		if res == "" {
			break
		} else {
			u, err := url.Parse(res)
			if err != nil {
				fmt.Printf("Error: not a valid URL (%s)\n", err.Error())
				break
			} else if u.Scheme != "http" && u.Scheme != "https" {
				fmt.Println("Error: not a valid HTTP/HTTPS URL")
				break
			}

			selfIssurURLs = append(selfIssurURLs, u.String())
		}
	}

	crlURLs := make([]string, 0, 10)
	for {
		fmt.Printf("Enter your CRL Distribution Points (URL) [empty to stop]: ")
		res := ReadString()
		if res == "" {
			break
		} else {
			u, err := url.Parse(res)
			if err != nil {
				fmt.Printf("Error: not a valid URL (%s)\n", err.Error())
				break
			} else if u.Scheme != "http" && u.Scheme != "https" {
				fmt.Println("Error: not a valid HTTP/HTTPS URL")
				break
			}

			crlURLs = append(crlURLs, u.String())
		}
	}

	fmt.Printf("Set a password for private key: ")
	password := ReadPassword()

	err = subject.SetCNIfEmpty()
	if err != nil {
		fmt.Printf("Error: %s\n", err)
		return
	}

	_, dirPath, err := ReadDir(homeICA, "ICA-", subject)
	if err != nil {
		fmt.Printf("Error: %s", err.Error())
		return
	}

	infoPath := path.Join(dirPath, "ica-info.gob")
	cert1Path := path.Join(dirPath, "cert.pem")
	cert2Path := path.Join(dirPath, "cert.cer")
	fullchain1Path := path.Join(dirPath, "fullchain.pem")
	fullchain2Path := path.Join(dirPath, "fullchain.cer")
	keyPath := path.Join(dirPath, "key.pem")
	spxPath := path.Join(dirPath, "cert.spx")
	pfxPath := path.Join(dirPath, "cert.pfx")

	if utils.IsExists(dirPath) {
		fmt.Printf("There is a duplicate file, it will be overwritten. Do you confirm to save the certificate?")
		if !ReadBoolDefaultNoPrint() {
			return
		}
	} else {
		fmt.Printf("Do you confirm to save the certificate?")
		if !ReadBoolDefaultYesPrint() {
			return
		}
	}

	err = os.MkdirAll(dirPath, 0600)
	if err != nil {
		fmt.Printf("Error: %s\n", err.Error())
		return
	}

	caCert, key, icaInfo, err := ica.CreateICA(infoPath, rcaInfo, cryptoType, keyLength, subject, keyUsage, extKeyUsage, maxPathLen, selfOcspURLs, selfIssurURLs, crlURLs, notBefore, notAfter, rcaCert, rcaKey)
	if err != nil {
		fmt.Printf("Error: %s\n", err.Error())
		return
	}

	err = icaInfo.SaveICAInfo()
	if err != nil {
		fmt.Printf("Error: %s\n", err.Error())
		return
	}

	err = utils.SaveCertificate(caCert, rcaFullchain, cert1Path, cert2Path, fullchain1Path, fullchain2Path)
	if err != nil {
		fmt.Printf("Error: %s\n", err.Error())
		return
	}

	err = utils.SavePrivateKey(key, password, keyPath)
	if err != nil {
		fmt.Printf("Error: %s\n", err.Error())
		return
	}

	err = utils.SaveSPX(key, password, caCert, rcaFullchain, spxPath)
	if err != nil {
		fmt.Printf("Error: %s\n", err.Error())
		return
	}

	err = utils.SavePFX(key, password, caCert, rcaFullchain, pfxPath)
	if err != nil {
		fmt.Printf("Error: %s\n", err.Error())
		return
	}

	fmt.Println("Success, save directory: ", dirPath)
}

func CreateICAFromICA() {
	icaCert, icaKey, icaFullchain, icaInfo, err := LoadICA()
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

	subject, err := ReadSubject()
	if err != nil {
		fmt.Printf("Error: %s\n", err.Error())
		return
	}

	fmt.Printf("Validity: ")
	validity := ReadTimeDuration(time.Hour * 24 * 365 * 5)

	notBefore := time.Now()
	notAfter := notBefore.Add(validity)

	keyUsage, err := ReadKeyUsage("ica")
	if err != nil {
		fmt.Printf("Error: %s\n", err.Error())
		return
	}

	extKeyUsage, err := ReadExtKeyUsage()
	if err != nil {
		fmt.Printf("Error: %s\n", err.Error())
		return
	}

	fmt.Printf("Set the ca max path len limit [-1 means no limit]: ")
	maxPathLen := ReadNumber()
	if maxPathLen < -1 {
		if icaCert.MaxPathLen != -1 {
			fmt.Printf("Error: bad max path len: path len must less than father ca")
			return
		}

		maxPathLen = -1
		fmt.Printf("OK, the CA has not limit to create ica.\n")
	} else if maxPathLen == 0 {
		if icaCert.MaxPathLen == 0 {
			fmt.Printf("Error: bad max path len: path len must less than father ca")
			return
		}
		fmt.Printf("OK, the CA can not to create ica.\n")
	} else {
		if icaCert.MaxPathLen != -1 && icaCert.MaxPathLen < maxPathLen {
			fmt.Printf("Error: bad max path len: path len must less than father ca")
			return
		}
		fmt.Printf("OK, CA can create %d layers of ica.\n", maxPathLen)
	}

	ocspURLs := make([]string, 0, 10)
	for {
		fmt.Printf("Enter your OCSP Server URL [empty to stop]: ")
		res := ReadString()
		if res == "" {
			break
		} else {
			u, err := url.Parse(res)
			if err != nil {
				fmt.Printf("Error: not a valid URL (%s)\n", err.Error())
				break
			} else if u.Scheme != "http" && u.Scheme != "https" {
				fmt.Println("Error: not a valid HTTP/HTTPS URL")
				break
			}

			ocspURLs = append(ocspURLs, u.String())
		}
	}

	issurURLs := make([]string, 0, 10)
	for {
		fmt.Printf("Enter your Issuing Certificate URL [empty to stop]: ")
		res := ReadString()
		if res == "" {
			break
		} else {
			u, err := url.Parse(res)
			if err != nil {
				fmt.Printf("Error: not a valid URL (%s)\n", err.Error())
				break
			} else if u.Scheme != "http" && u.Scheme != "https" {
				fmt.Println("Error: not a valid HTTP/HTTPS URL")
				break
			}

			issurURLs = append(issurURLs, u.String())
		}
	}

	crlURLs := make([]string, 0, 10)
	for {
		fmt.Printf("Enter your CRL Distribution Points (URL) [empty to stop]: ")
		res := ReadString()
		if res == "" {
			break
		} else {
			u, err := url.Parse(res)
			if err != nil {
				fmt.Printf("Error: not a valid URL (%s)\n", err.Error())
				break
			} else if u.Scheme != "http" && u.Scheme != "https" {
				fmt.Println("Error: not a valid HTTP/HTTPS URL")
				break
			}

			crlURLs = append(crlURLs, u.String())
		}
	}

	fmt.Printf("Set a password for private key: ")
	password := ReadPassword()

	err = subject.SetCNIfEmpty()
	if err != nil {
		fmt.Printf("Error: %s\n", err)
		return
	}

	_, dirPath, err := ReadDir(homeICA, "ICA-", subject)
	if err != nil {
		fmt.Printf("Error: %s", err.Error())
		return
	}

	infoPath := path.Join(dirPath, "ica-info.gob")
	cert1Path := path.Join(dirPath, "cert.pem")
	cert2Path := path.Join(dirPath, "cert.cer")
	fullchain1Path := path.Join(dirPath, "fullchain.pem")
	fullchain2Path := path.Join(dirPath, "fullchain.cer")
	keyPath := path.Join(dirPath, "key.pem")
	spxPath := path.Join(dirPath, "cert.spx")
	pfxPath := path.Join(dirPath, "cert.pfx")

	if utils.IsExists(cert1Path) || utils.IsExists(cert2Path) || utils.IsExists(fullchain1Path) || utils.IsExists(fullchain2Path) || utils.IsExists(keyPath) {
		fmt.Printf("There is a duplicate file, it will be overwritten. Do you confirm to save the certificate?")
		if !ReadBoolDefaultNoPrint() {
			return
		}
	} else {
		fmt.Printf("Do you confirm to save the certificate?")
		if !ReadBoolDefaultYesPrint() {
			return
		}
	}

	err = os.MkdirAll(dirPath, 0600)
	if err != nil {
		fmt.Printf("Error: %s\n", err.Error())
		return
	}

	caCert, key, newIcaInfo, err := ica.CreateICA(infoPath, icaInfo, cryptoType, keyLength, subject, keyUsage, extKeyUsage, maxPathLen, ocspURLs, issurURLs, crlURLs, notBefore, notAfter, icaCert, icaKey)
	if err != nil {
		fmt.Printf("Error: %s\n", err.Error())
		return
	}

	err = newIcaInfo.SaveICAInfo()
	if err != nil {
		fmt.Printf("Error: %s\n", err.Error())
		return
	}

	err = utils.SaveCertificate(caCert, icaFullchain, cert1Path, cert2Path, fullchain1Path, fullchain2Path)
	if err != nil {
		fmt.Printf("Error: %s\n", err.Error())
		return
	}

	err = utils.SavePrivateKey(key, password, keyPath)
	if err != nil {
		fmt.Printf("Error: %s\n", err.Error())
		return
	}

	err = utils.SaveSPX(key, password, caCert, icaFullchain, spxPath)
	if err != nil {
		fmt.Printf("Error: %s\n", err.Error())
		return
	}

	err = utils.SavePFX(key, password, caCert, icaFullchain, pfxPath)
	if err != nil {
		fmt.Printf("Error: %s\n", err.Error())
		return
	}

	fmt.Println("Success, save directory: ", dirPath)
}

func CreateUserCertFromRCA() {
	rcaCert, rcaKey, rcaFullchain, rcaInfo, err := LoadRCA()
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

	subject, err := ReadSubject()
	if err != nil {
		fmt.Printf("Error: %s\n", err.Error())
		return
	}

	fmt.Printf("Validity: ")
	validity := ReadTimeDuration(time.Hour * 24 * 365 * 5)

	notBefore := time.Now()
	notAfter := notBefore.Add(validity)

	keyUsage, err := ReadKeyUsage("auto_cert")
	if err != nil {
		fmt.Printf("Error: %s\n", err.Error())
		return
	}

	extKeyUsage, err := ReadExtKeyUsage()
	if err != nil {
		fmt.Printf("Error: %s\n", err.Error())
		return
	}

	domains, err := ReadMoreStringWithPolicy("Enter your domain", func(s string) (string, error) {
		if !utils.IsValidDomain(s) {
			return "", NewWarning("not a valid domain")
		}
		return s, nil
	})
	if err != nil {
		fmt.Printf("Error: %s\n", err.Error())
		return
	}

	ips, err := ReadMoreStringWithPolicy("Enter your IPv4/IPv6", func(s string) (net.IP, error) {
		ip := net.ParseIP(s)
		if ip == nil {
			return nil, NewWarning("not a valid ip")
		}
		return ip, nil
	})
	if err != nil {
		fmt.Printf("Error: %s\n", err.Error())
		return
	}

	fmt.Printf("Now we need to add your email (if you have), do you want to check it from DNS? ")
	checkEmail := ReadBoolDefaultYesPrint()
	StillAddEmail := true
	if checkEmail {
		fmt.Printf("Now we will check the email when you add it, do you want to still add it when dns check failed? ")
		StillAddEmail = ReadBoolDefaultYesPrint()
	}

	emails, err := ReadMoreStringWithPolicy("Enter your email", func(s string) (string, error) {
		email, err := mail.ParseAddress(s)
		if err != nil {
			return "", NewWarningF("not a valid email (%s)", err.Error())
		} else if !utils.IsValidEmail(email.Address) {
			return "", NewWarning("not a valid email (%s)")
		} else if checkEmail {
			if !utils.CheckEmailMX(email) {
				if !StillAddEmail {
					return "", NewWarningF("email (%s) check failed\n", s)
				}
			}
		}
		return email.Address, nil
	})
	if err != nil {
		fmt.Printf("Error: %s\n", err.Error())
		return
	}

	urls, err := ReadMoreStringWithPolicy("Enter your URL", func(s string) (*url.URL, error) {
		u, err := url.Parse(s)
		if err != nil {
			return nil, NewWarning("not a valid url")
		}

		return u, nil
	})
	if err != nil {
		fmt.Printf("Error: %s\n", err.Error())
		return
	}

	domainsR := make([]string, 0, 10)
	domainsRS := make([]string, 0, 10)
	ipsR := make([]net.IP, 0, 10)

	err = ReadMoreStringWithProcess("Enter your domain", func(s string) error {
		if !utils.IsValidDomain(s) {
			return NewWarning("not a valid domain")
		}

		domainsR = append(domainsR, s)

		ipsN, err := utils.ResolveDomainToIPs(s)
		if err != nil {
			return NewWarningF("domain resolve error (%s)\n", err.Error())
		} else if ipsN == nil {
			return NewWarning("domain without ip")
		}

		fmt.Printf("Domain %s resolve result: \n", s)
		for _, i := range ipsN {
			fmt.Printf("  - %s\n", i.String())
		}
		fmt.Printf("Domain %s resolve finished.\n", s)

		domainsRS = append(domainsRS, s)
		ipsR = append(ipsR, ipsN...)

		return nil
	})
	if err != nil {
		fmt.Printf("Error: %s\n", err.Error())
		return
	}

	fmt.Printf("Add the domain in cert? ")
	if ReadBoolDefaultYesPrint() {
		fmt.Printf("Add the all of the domain (include which the resolve failed) in cert? ")
		if ReadBoolDefaultYesPrint() {
			domains = append(domains, domainsR...)
		} else {
			domains = append(domains, domainsRS...)
		}
	}

	ips = append(ips, ipsR...)

	fmt.Printf("Set a password for private key: ")
	password := ReadPassword()

	err = subject.SetCNIfEmpty()
	if err != nil {
		fmt.Printf("Error: %s\n", err)
		return
	}

	_, dirPath, err := ReadDir(homeCert, "CERT-", subject)
	if err != nil {
		fmt.Printf("Error: %s", err.Error())
		return
	}

	infoPath := path.Join(dirPath, "cert-info.gob")
	cert1Path := path.Join(dirPath, "cert.pem")
	cert2Path := path.Join(dirPath, "cert.cer")
	fullchain1Path := path.Join(dirPath, "fullchain.pem")
	fullchain2Path := path.Join(dirPath, "fullchain.cer")
	keyPath := path.Join(dirPath, "key.pem")
	spxPath := path.Join(dirPath, "cert.spx")
	pfxPath := path.Join(dirPath, "cert.pfx")

	if utils.IsExists(cert1Path) || utils.IsExists(cert2Path) || utils.IsExists(fullchain1Path) || utils.IsExists(fullchain2Path) || utils.IsExists(keyPath) {
		fmt.Printf("There is a duplicate file, it will be overwritten. Do you confirm to save the certificate?")
		if !ReadBoolDefaultNoPrint() {
			return
		}
	} else {
		fmt.Printf("Do you confirm to save the certificate?")
		if !ReadBoolDefaultYesPrint() {
			return
		}
	}

	err = os.MkdirAll(dirPath, 0600)
	if err != nil {
		fmt.Printf("Error: %s\n", err.Error())
		return
	}

	userCert, key, certInfo, err := cert.CreateCert(infoPath, rcaInfo, cryptoType, keyLength, subject, keyUsage, extKeyUsage, domains, ips, emails, urls, notBefore, notAfter, rcaCert, rcaKey)
	if err != nil {
		fmt.Printf("Error: %s\n", err.Error())
		return
	}

	err = certInfo.SaveCertInfo()
	if err != nil {
		fmt.Printf("Error: %s\n", err.Error())
		return
	}

	err = utils.SaveCertificate(userCert, rcaFullchain, cert1Path, cert2Path, fullchain1Path, fullchain2Path)
	if err != nil {
		fmt.Printf("Error: %s\n", err.Error())
		return
	}

	err = utils.SavePrivateKey(key, password, keyPath)
	if err != nil {
		fmt.Printf("Error: %s\n", err.Error())
		return
	}

	err = utils.SaveSPX(key, password, userCert, rcaFullchain, spxPath)
	if err != nil {
		fmt.Printf("Error: %s\n", err.Error())
		return
	}

	err = utils.SavePFX(key, password, userCert, rcaFullchain, pfxPath)
	if err != nil {
		fmt.Printf("Error: %s\n", err.Error())
		return
	}

	fmt.Println("Success, save directory: ", dirPath)
}

func CreateUserCertFromICA() {
	icaCert, icaKey, icaFullchain, icaInfo, err := LoadICA()
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

	subject, err := ReadSubject()
	if err != nil {
		fmt.Printf("Error: %s\n", err.Error())
		return
	}

	fmt.Printf("Validity: ")
	validity := ReadTimeDuration(time.Hour * 24 * 365 * 5)

	notBefore := time.Now()
	notAfter := notBefore.Add(validity)

	keyUsage, err := ReadKeyUsage("auto_cert")
	if err != nil {
		fmt.Printf("Error: %s\n", err.Error())
		return
	}

	extKeyUsage, err := ReadExtKeyUsage()
	if err != nil {
		fmt.Printf("Error: %s\n", err.Error())
		return
	}

	domains, err := ReadMoreStringWithPolicy("Enter your domain", func(s string) (string, error) {
		if !utils.IsValidDomain(s) {
			return "", NewWarning("not a valid domain")
		}
		return s, nil
	})
	if err != nil {
		fmt.Printf("Error: %s\n", err.Error())
		return
	}

	ips, err := ReadMoreStringWithPolicy("Enter your IPv4/IPv6", func(s string) (net.IP, error) {
		ip := net.ParseIP(s)
		if ip == nil {
			return nil, NewWarning("not a valid ip")
		}
		return ip, nil
	})
	if err != nil {
		fmt.Printf("Error: %s\n", err.Error())
		return
	}

	fmt.Printf("Now we need to add your email (if you have), do you want to check it from DNS? ")
	checkEmail := ReadBoolDefaultYesPrint()
	StillAddEmail := true
	if checkEmail {
		fmt.Printf("Now we will check the email when you add it, do you want to still add it when dns check failed? ")
		StillAddEmail = ReadBoolDefaultYesPrint()
	}

	emails, err := ReadMoreStringWithPolicy("Enter your email", func(s string) (string, error) {
		email, err := mail.ParseAddress(s)
		if err != nil {
			return "", NewWarningF("not a valid email (%s)", err.Error())
		} else if !utils.IsValidEmail(email.Address) {
			return "", NewWarning("not a valid email (%s)")
		} else if checkEmail {
			if !utils.CheckEmailMX(email) {
				if !StillAddEmail {
					return "", NewWarningF("email (%s) check failed\n", s)
				}
			}
		}
		return email.Address, nil
	})
	if err != nil {
		fmt.Printf("Error: %s\n", err.Error())
		return
	}

	urls, err := ReadMoreStringWithPolicy("Enter your URL", func(s string) (*url.URL, error) {
		u, err := url.Parse(s)
		if err != nil {
			return nil, NewWarning("not a valid url")
		}

		return u, nil
	})
	if err != nil {
		fmt.Printf("Error: %s\n", err.Error())
		return
	}

	domainsR := make([]string, 0, 10)
	domainsRS := make([]string, 0, 10)
	ipsR := make([]net.IP, 0, 10)

	err = ReadMoreStringWithProcess("Enter your domain", func(s string) error {
		if !utils.IsValidDomain(s) {
			return NewWarning("not a valid domain")
		}

		domainsR = append(domainsR, s)

		ipsN, err := utils.ResolveDomainToIPs(s)
		if err != nil {
			return NewWarningF("domain resolve error (%s)\n", err.Error())
		} else if ipsN == nil {
			return NewWarning("domain without ip")
		}

		fmt.Printf("Domain %s resolve result: \n", s)
		for _, i := range ipsN {
			fmt.Printf("  - %s\n", i.String())
		}
		fmt.Printf("Domain %s resolve finished.\n", s)

		domainsRS = append(domainsRS, s)
		ipsR = append(ipsR, ipsN...)

		return nil
	})
	if err != nil {
		fmt.Printf("Error: %s\n", err.Error())
		return
	}

	fmt.Printf("Add the domain in cert? ")
	if ReadBoolDefaultYesPrint() {
		fmt.Printf("Add the all of the domain (include which the resolve failed) in cert? ")
		if ReadBoolDefaultYesPrint() {
			domains = append(domains, domainsR...)
		} else {
			domains = append(domains, domainsRS...)
		}
	}

	ips = append(ips, ipsR...)

	fmt.Printf("Set a password for private key: ")
	password := ReadPassword()

	err = subject.SetCNIfEmpty()
	if err != nil {
		fmt.Printf("Error: %s\n", err)
		return
	}

	_, dirPath, err := ReadDir(homeCert, "CERT-", subject)
	if err != nil {
		fmt.Printf("Error: %s", err.Error())
		return
	}

	infoPath := path.Join(dirPath, "cert-info.gob")
	cert1Path := path.Join(dirPath, "cert.pem")
	cert2Path := path.Join(dirPath, "cert.cer")
	fullchain1Path := path.Join(dirPath, "fullchain.pem")
	fullchain2Path := path.Join(dirPath, "fullchain.cer")
	keyPath := path.Join(dirPath, "key.pem")
	spxPath := path.Join(dirPath, "cert.spx")
	pfxPath := path.Join(dirPath, "cert.pfx")

	if utils.IsExists(cert1Path) || utils.IsExists(cert2Path) || utils.IsExists(fullchain1Path) || utils.IsExists(fullchain2Path) || utils.IsExists(keyPath) {
		fmt.Printf("There is a duplicate file, it will be overwritten. Do you confirm to save the certificate?")
		if !ReadBoolDefaultNoPrint() {
			return
		}
	} else {
		fmt.Printf("Do you confirm to save the certificate?")
		if !ReadBoolDefaultYesPrint() {
			return
		}
	}

	err = os.MkdirAll(dirPath, 0600)
	if err != nil {
		fmt.Printf("Error: %s\n", err.Error())
		return
	}

	userCert, key, certInfo, err := cert.CreateCert(infoPath, icaInfo, cryptoType, keyLength, subject, keyUsage, extKeyUsage, domains, ips, emails, urls, notBefore, notAfter, icaCert, icaKey)
	if err != nil {
		fmt.Printf("Error: %s\n", err.Error())
		return
	}

	err = certInfo.SaveCertInfo()
	if err != nil {
		fmt.Printf("Error: %s\n", err.Error())
		return
	}

	err = utils.SaveCertificate(userCert, icaFullchain, cert1Path, cert2Path, fullchain1Path, fullchain2Path)
	if err != nil {
		fmt.Printf("Error: %s\n", err.Error())
		return
	}

	err = utils.SavePrivateKey(key, password, keyPath)
	if err != nil {
		fmt.Printf("Error: %s\n", err.Error())
		return
	}

	err = utils.SaveSPX(key, password, userCert, icaFullchain, spxPath)
	if err != nil {
		fmt.Printf("Error: %s\n", err.Error())
		return
	}

	err = utils.SavePFX(key, password, userCert, icaFullchain, pfxPath)
	if err != nil {
		fmt.Printf("Error: %s\n", err.Error())
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

	subject, err := ReadSubject()
	if err != nil {
		fmt.Printf("Error: %s\n", err.Error())
		return
	}

	fmt.Printf("Validity: ")
	validity := ReadTimeDuration(time.Hour * 24 * 365 * 5)

	notBefore := time.Now()
	notAfter := notBefore.Add(validity)

	keyUsage, err := ReadKeyUsage("auto_cert")
	if err != nil {
		fmt.Printf("Error: %s\n", err.Error())
		return
	}

	extKeyUsage, err := ReadExtKeyUsage()
	if err != nil {
		fmt.Printf("Error: %s\n", err.Error())
		return
	}

	domains, err := ReadMoreStringWithPolicy("Enter your domain", func(s string) (string, error) {
		if !utils.IsValidDomain(s) {
			return "", NewWarning("not a valid domain")
		}
		return s, nil
	})
	if err != nil {
		fmt.Printf("Error: %s\n", err.Error())
		return
	}

	ips, err := ReadMoreStringWithPolicy("Enter your IPv4/IPv6", func(s string) (net.IP, error) {
		ip := net.ParseIP(s)
		if ip == nil {
			return nil, NewWarning("not a valid ip")
		}
		return ip, nil
	})
	if err != nil {
		fmt.Printf("Error: %s\n", err.Error())
		return
	}

	fmt.Printf("Now we need to add your email (if you have), do you want to check it from DNS? ")
	checkEmail := ReadBoolDefaultYesPrint()
	StillAddEmail := true
	if checkEmail {
		fmt.Printf("Now we will check the email when you add it, do you want to still add it when dns check failed? ")
		StillAddEmail = ReadBoolDefaultYesPrint()
	}

	emails, err := ReadMoreStringWithPolicy("Enter your email", func(s string) (string, error) {
		email, err := mail.ParseAddress(s)
		if err != nil {
			return "", NewWarningF("not a valid email (%s)", err.Error())
		} else if !utils.IsValidEmail(email.Address) {
			return "", NewWarning("not a valid email (%s)")
		} else if checkEmail {
			if !utils.CheckEmailMX(email) {
				if !StillAddEmail {
					return "", NewWarningF("email (%s) check failed\n", s)
				}
			}
		}
		return email.Address, nil
	})
	if err != nil {
		fmt.Printf("Error: %s\n", err.Error())
		return
	}

	urls, err := ReadMoreStringWithPolicy("Enter your URL", func(s string) (*url.URL, error) {
		u, err := url.Parse(s)
		if err != nil {
			return nil, NewWarning("not a valid url")
		}

		return u, nil
	})
	if err != nil {
		fmt.Printf("Error: %s\n", err.Error())
		return
	}

	domainsR := make([]string, 0, 10)
	domainsRS := make([]string, 0, 10)
	ipsR := make([]net.IP, 0, 10)

	err = ReadMoreStringWithProcess("Enter your domain", func(s string) error {
		if !utils.IsValidDomain(s) {
			return NewWarning("not a valid domain")
		}

		domainsR = append(domainsR, s)

		ipsN, err := utils.ResolveDomainToIPs(s)
		if err != nil {
			return NewWarningF("domain resolve error (%s)\n", err.Error())
		} else if ipsN == nil {
			return NewWarning("domain without ip")
		}

		fmt.Printf("Domain %s resolve result: \n", s)
		for _, i := range ipsN {
			fmt.Printf("  - %s\n", i.String())
		}
		fmt.Printf("Domain %s resolve finished.\n", s)

		domainsRS = append(domainsRS, s)
		ipsR = append(ipsR, ipsN...)

		return nil
	})
	if err != nil {
		fmt.Printf("Error: %s\n", err.Error())
		return
	}

	fmt.Printf("Add the domain in cert? ")
	if ReadBoolDefaultYesPrint() {
		fmt.Printf("Add the all of the domain (include which the resolve failed) in cert? ")
		if ReadBoolDefaultYesPrint() {
			domains = append(domains, domainsR...)
		} else {
			domains = append(domains, domainsRS...)
		}
	}

	ips = append(ips, ipsR...)

	ocspURLs := make([]string, 0, 10)
	for {
		fmt.Printf("Enter your OCSP Server URL [empty to stop]: ")
		res := ReadString()
		if res == "" {
			break
		} else {
			u, err := url.Parse(res)
			if err != nil {
				fmt.Printf("Error: not a valid URL (%s)\n", err.Error())
				break
			} else if u.Scheme != "http" && u.Scheme != "https" {
				fmt.Println("Error: not a valid HTTP/HTTPS URL")
				break
			}

			ocspURLs = append(ocspURLs, u.String())
		}
	}

	issurURLs := make([]string, 0, 10)
	for {
		fmt.Printf("Enter your Issuing Certificate URL [empty to stop]: ")
		res := ReadString()
		if res == "" {
			break
		} else {
			u, err := url.Parse(res)
			if err != nil {
				fmt.Printf("Error: not a valid URL (%s)\n", err.Error())
				break
			} else if u.Scheme != "http" && u.Scheme != "https" {
				fmt.Println("Error: not a valid HTTP/HTTPS URL")
				break
			}

			issurURLs = append(issurURLs, u.String())
		}
	}

	crlURLs := make([]string, 0, 10)
	for {
		fmt.Printf("Enter your CRL Distribution Points (URL) [empty to stop]: ")
		res := ReadString()
		if res == "" {
			break
		} else {
			u, err := url.Parse(res)
			if err != nil {
				fmt.Printf("Error: not a valid URL (%s)\n", err.Error())
				break
			} else if u.Scheme != "http" && u.Scheme != "https" {
				fmt.Println("Error: not a valid HTTP/HTTPS URL")
				break
			}

			crlURLs = append(crlURLs, u.String())
		}
	}

	fmt.Printf("Set a password for private key: ")
	password := ReadPassword()

	err = subject.SetCNIfEmpty()
	if err != nil {
		fmt.Printf("Error: %s\n", err)
		return
	}

	_, dirPath, err := ReadDir(homeCert, "SELF-CERT-", subject)
	if err != nil {
		fmt.Printf("Error: %s", err.Error())
		return
	}

	infoPath := path.Join(dirPath, "cert-info.gob")
	cert1Path := path.Join(dirPath, "cert.pem")
	cert2Path := path.Join(dirPath, "cert.cer")
	fullchain1Path := path.Join(dirPath, "fullchain.pem")
	fullchain2Path := path.Join(dirPath, "fullchain.cer")
	keyPath := path.Join(dirPath, "key.pem")
	spxPath := path.Join(dirPath, "cert.spx")
	pfxPath := path.Join(dirPath, "cert.pfx")

	if utils.IsExists(cert1Path) || utils.IsExists(cert2Path) || utils.IsExists(fullchain1Path) || utils.IsExists(fullchain2Path) || utils.IsExists(keyPath) {
		fmt.Printf("There is a duplicate file, it will be overwritten. Do you confirm to save the certificate?")
		if !ReadBoolDefaultNoPrint() {
			return
		}
	} else {
		fmt.Printf("Do you confirm to save the certificate?")
		if !ReadBoolDefaultYesPrint() {
			return
		}
	}

	err = os.MkdirAll(dirPath, 0600)
	if err != nil {
		fmt.Printf("Error: %s\n", err.Error())
		return
	}

	userCert, key, certInfo, err := cert.CreateSelfCert(infoPath, cryptoType, keyLength, subject, keyUsage, extKeyUsage, domains, ips, emails, urls, ocspURLs, issurURLs, crlURLs, notBefore, notAfter)
	if err != nil {
		fmt.Printf("Error: %s\n", err.Error())
		return
	}

	err = certInfo.SaveSelfCert()
	if err != nil {
		fmt.Printf("Error: %s\n", err.Error())
		return
	}

	err = utils.SaveCertificate(userCert, []byte{}, cert1Path, cert2Path, fullchain1Path, fullchain2Path)
	if err != nil {
		fmt.Printf("Error: %s\n", err.Error())
		return
	}

	err = utils.SavePrivateKey(key, password, keyPath)
	if err != nil {
		fmt.Printf("Error: %s\n", err.Error())
		return
	}

	err = utils.SaveSPX(key, password, userCert, []byte{}, spxPath)
	if err != nil {
		fmt.Printf("Error: %s\n", err.Error())
		return
	}

	err = utils.SavePFX(key, password, userCert, []byte{}, pfxPath)
	if err != nil {
		fmt.Printf("Error: %s\n", err.Error())
		return
	}

	fmt.Println("Success, save directory: ", dirPath)
}
