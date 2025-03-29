package mycav1

import (
	"fmt"
	"github.com/SongZihuan/MyCA/src/cert"
	"github.com/SongZihuan/MyCA/src/ica"
	"github.com/SongZihuan/MyCA/src/rootca"
	"github.com/SongZihuan/MyCA/src/sysinfo"
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

	fmt.Printf("Org: ")
	org := ReadString()

	fmt.Printf("Common Name: ")
	cn := ReadString()

	fmt.Printf("Validity: ")
	validity := ReadTimeDuration(time.Hour * 24 * 365 * 10)

	notBefore := time.Now()
	notAfter := notBefore.Add(validity)

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

	org, cn = sysinfo.CreateCASubject(org, cn)

	dirPath := path.Join(home, "rca", fmt.Sprintf("%s-%s", org, cn))
	infoFile := path.Join(dirPath, "rca-info.gob")
	cert1Path := path.Join(dirPath, "cert.pem")
	cert2Path := path.Join(dirPath, "cert.cer")
	fullchain1Path := path.Join(dirPath, "fullchain.pem")
	fullchain2Path := path.Join(dirPath, "fullchain.cer")
	keyPath := path.Join(dirPath, "key.pem")

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

	err := os.MkdirAll(dirPath, 0600)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	caCert, key, rcaInfo, err := rootca.CreateRCA(infoFile, cryptoType, keyLength, org, cn, ocspURLs, issurURLs, crlURLs, notBefore, notAfter)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	err = rcaInfo.SaveRCAInfo()
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

	fmt.Printf("Org: ")
	org := ReadString()

	fmt.Printf("Common Name: ")
	cn := ReadString()

	org, cn = sysinfo.CreateCASubject(org, cn)

	fmt.Printf("Validity: ")
	validity := ReadTimeDuration(time.Hour * 24 * 365 * 5)

	notBefore := time.Now()
	notAfter := notBefore.Add(validity)

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

	dirPath := path.Join(home, "ica", fmt.Sprintf("%s-%s", org, cn))
	infoFile := path.Join(dirPath, "rca-info.gob")
	cert1Path := path.Join(dirPath, "cert.pem")
	cert2Path := path.Join(dirPath, "cert.cer")
	fullchain1Path := path.Join(dirPath, "fullchain.pem")
	fullchain2Path := path.Join(dirPath, "fullchain.cer")
	keyPath := path.Join(dirPath, "key.pem")

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
		fmt.Println("Error:", err)
		return
	}

	caCert, key, icaInfo, err := ica.CreateICA(infoFile, rcaInfo, cryptoType, keyLength, org, cn, selfOcspURLs, selfIssurURLs, crlURLs, notBefore, notAfter, rcaCert, rcaKey)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	err = icaInfo.SaveICAInfo()
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

	fmt.Printf("Org: ")
	org := ReadString()

	fmt.Printf("Common Name: ")
	cn := ReadString()

	org, cn = sysinfo.CreateCASubject(org, cn)

	fmt.Printf("Validity: ")
	validity := ReadTimeDuration(time.Hour * 24 * 365 * 5)

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

	notBefore := time.Now()
	notAfter := notBefore.Add(validity)

	dirPath := path.Join(home, "ica", fmt.Sprintf("%s-%s", org, cn))
	infoFile := path.Join(dirPath, "ica-info.gob")
	cert1Path := path.Join(dirPath, "cert.pem")
	cert2Path := path.Join(dirPath, "cert.cer")
	fullchain1Path := path.Join(dirPath, "fullchain.pem")
	fullchain2Path := path.Join(dirPath, "fullchain.cer")
	keyPath := path.Join(dirPath, "key.pem")

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
		fmt.Println("Error:", err)
		return
	}

	caCert, key, newIcaInfo, err := ica.CreateICA(infoFile, icaInfo, cryptoType, keyLength, org, cn, ocspURLs, issurURLs, crlURLs, notBefore, notAfter, icaCert, icaKey)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	err = newIcaInfo.SaveICAInfo()
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

	fmt.Printf("Org: ")
	org := ReadString()

	fmt.Printf("Common Name: ")
	cn := ReadString()

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
		} else if !utils.IsValidDomain(res) {
			fmt.Println("Error: not a valid domain")
			break
		}
		domains = append(domains, res)
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
				break
			}

			ips = append(ips, ip)
		}
	}

	fmt.Printf("Now we need to add your email (if you have), do you want to check it from DNS? ")
	checkEmail := ReadBoolDefaultYesPrint()
	StillAddEmail := true
	if checkEmail {
		fmt.Printf("Now we will check the email when you add it, do you want to still add it when dns check failed? ")
		StillAddEmail = ReadBoolDefaultYesPrint()
	}

	emails := make([]string, 0, 10)
	for {
		fmt.Printf("Enter your email [empty to stop]: ")
		res := ReadString()
		if res == "" {
			break
		} else {
			email, err := mail.ParseAddress(res)
			if err != nil {
				fmt.Printf("Error: not a valid email (%s)\n", err.Error())
				break
			} else if !utils.IsValidEmail(email.Address) {
				fmt.Println("Error: not a valid email")
				break
			} else if checkEmail {
				if utils.CheckEmailMX(email) {
					fmt.Printf("OK: email (%s) check success\n", res)
				} else {
					if StillAddEmail {
						fmt.Printf("Warn: email (%s) check failed\n", res)
					} else {
						fmt.Printf("Error: email (%s) check failed\n", res)
						break
					}
				}
			}

			emails = append(emails, email.Address)
		}
	}

	urls := make([]*url.URL, 0, 10)
	for {
		fmt.Printf("Enter your URL [empty to stop]: ")
		res := ReadString()
		if res == "" {
			break
		} else {
			u, err := url.Parse(res)
			if err != nil {
				fmt.Printf("Error: not a valid URL (%s)\n", err.Error())
				break
			}

			urls = append(urls, u)
		}
	}

	domainsR := make([]string, 0, 10)
	domainsRS := make([]string, 0, 10)
	ipsR := make([]net.IP, 0, 10)
	for {
		fmt.Printf("Enter your domain and it will resolve to ip [empty to stop]: ")
		res := ReadString()
		if res == "" {
			break
		} else if !utils.IsValidDomain(res) {
			fmt.Println("Error: not a valid domain")
			break
		}

		domainsR = append(domainsR, res)

		ipsN, err := utils.ResolveDomainToIPs(res)
		if err != nil {
			fmt.Printf("Error: domain resolve error (%s)\n", err.Error())
			break
		} else if ipsN == nil {
			fmt.Println("Error: domain without ip")
			break
		} else {
			fmt.Printf("Domain %s resolve result: \n", res)
			for _, i := range ipsN {
				fmt.Printf("  - %s\n", i.String())
			}
			fmt.Printf("Domain %s resolve finished.\n", res)
		}

		domainsRS = append(domainsRS, res)
		ipsR = append(ipsR, ipsN...)
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

	org, cn = sysinfo.CreateCASubjectLong(org, cn, domains, ips, emails, urls)

	fmt.Printf("Set a password for private key: ")
	password := ReadPassword()

	dirPath := path.Join(home, "cert", fmt.Sprintf("%s-%s-%s-%s-%s", rcaCert.Subject.Organization[0], rcaCert.Subject.CommonName, org, cn, notBefore.Format("2006-01-02-15-04-05")))
	infoPath := path.Join(dirPath, "cert-info.gob")
	cert1Path := path.Join(dirPath, "cert.pem")
	cert2Path := path.Join(dirPath, "cert.cer")
	fullchain1Path := path.Join(dirPath, "fullchain.pem")
	fullchain2Path := path.Join(dirPath, "fullchain.cer")
	keyPath := path.Join(dirPath, "key.pem")

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
		fmt.Println("Error:", err)
		return
	}

	userCert, key, certInfo, err := cert.CreateCert(infoPath, rcaInfo, cryptoType, keyLength, org, cn, domains, ips, emails, urls, notBefore, notAfter, rcaCert, rcaKey)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	err = certInfo.SaveCertInfo()
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

	fmt.Printf("Org: ")
	org := ReadString()

	fmt.Printf("Common Name: ")
	cn := ReadString()

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

	fmt.Printf("Now we need to add your email (if you have), do you want to check it from DNS? ")
	checkEmail := ReadBoolDefaultYesPrint()
	StillAddEmail := true
	if checkEmail {
		fmt.Printf("Now we will check the email when you add it, do you want to still add it when dns check failed? ")
		StillAddEmail = ReadBoolDefaultYesPrint()
	}

	emails := make([]string, 0, 10)
	for {
		fmt.Printf("Enter your email [empty to stop]: ")
		res := ReadString()
		if res == "" {
			break
		} else {
			email, err := mail.ParseAddress(res)
			if err != nil {
				fmt.Printf("Error: not a valid email (%s)\n", err.Error())
				break
			} else if !utils.IsValidEmail(email.Address) {
				fmt.Println("Error: not a valid email")
				break
			} else if checkEmail {
				if utils.CheckEmailMX(email) {
					fmt.Printf("OK: email (%s) check success\n", res)
				} else {
					if StillAddEmail {
						fmt.Printf("Warn: email (%s) check failed\n", res)
					} else {
						fmt.Printf("Error: email (%s) check failed\n", res)
						break
					}
				}
			}

			emails = append(emails, email.Address)
		}
	}

	urls := make([]*url.URL, 0, 10)
	for {
		fmt.Printf("Enter your URL [empty to stop]: ")
		res := ReadString()
		if res == "" {
			break
		} else {
			u, err := url.Parse(res)
			if err != nil {
				fmt.Printf("Error: not a valid URL (%s)\n", err.Error())
				break
			}

			urls = append(urls, u)
		}
	}

	domainsR := make([]string, 0, 10)
	domainsRS := make([]string, 0, 10)
	ipsR := make([]net.IP, 0, 10)
	for {
		fmt.Printf("Enter your domain and it will resolve to ip [empty to stop]: ")
		res := ReadString()
		if res == "" {
			break
		} else if !utils.IsValidDomain(res) {
			fmt.Println("Error: not a valid domain")
			break
		}

		domainsR = append(domainsR, res)

		ipsN, err := utils.ResolveDomainToIPs(res)
		if err != nil {
			fmt.Printf("Error: domain resolve error (%s)\n", err.Error())
			break
		} else if ipsN == nil {
			fmt.Println("Error: domain without ip")
			break
		} else {
			fmt.Printf("Domain %s resolve result: \n", res)
			for _, i := range ipsN {
				fmt.Printf("  - %s\n", i.String())
			}
			fmt.Printf("Domain %s resolve finished.\n", res)
		}

		domainsRS = append(domainsRS, res)
		ipsR = append(ipsR, ipsN...)
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

	org, cn = sysinfo.CreateCASubjectLong(org, cn, domains, ips, emails, urls)

	fmt.Printf("Set a password for private key: ")
	password := ReadPassword()

	dirPath := path.Join(home, "cert", fmt.Sprintf("%s-%s-%s-%s-%s", icaCert.Subject.Organization[0], icaCert.Subject.CommonName, org, cn, notBefore.Format("2006-01-02-15-04-05")))
	infoPath := path.Join(dirPath, "cert-info.gob")
	cert1Path := path.Join(dirPath, "cert.pem")
	cert2Path := path.Join(dirPath, "cert.cer")
	fullchain1Path := path.Join(dirPath, "fullchain.pem")
	fullchain2Path := path.Join(dirPath, "fullchain.cer")
	keyPath := path.Join(dirPath, "key.pem")

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
		fmt.Println("Error:", err)
		return
	}

	userCert, key, certInfo, err := cert.CreateCert(infoPath, icaInfo, cryptoType, keyLength, org, cn, domains, ips, emails, urls, notBefore, notAfter, icaCert, icaKey)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	err = certInfo.SaveCertInfo()
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

	fmt.Printf("Common Name: ")
	cn := ReadString()

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
		} else if !utils.IsValidDomain(res) {
			fmt.Println("Error: not a valid domain")
			break
		}
		domains = append(domains, res)
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
				break
			}

			ips = append(ips, ip)
		}
	}

	fmt.Printf("Now we need to add your email (if you have), do you want to check it from DNS? ")
	checkEmail := ReadBoolDefaultYesPrint()
	StillAddEmail := true
	if checkEmail {
		fmt.Printf("Now we will check the email when you add it, do you want to still add it when dns check failed? ")
		StillAddEmail = ReadBoolDefaultYesPrint()
	}

	emails := make([]string, 0, 10)
	for {
		fmt.Printf("Enter your email [empty to stop]: ")
		res := ReadString()
		if res == "" {
			break
		} else {
			email, err := mail.ParseAddress(res)
			if err != nil {
				fmt.Printf("Error: not a valid email (%s)\n", err.Error())
				break
			} else if !utils.IsValidEmail(email.Address) {
				fmt.Println("Error: not a valid email")
				break
			} else if checkEmail {
				if utils.CheckEmailMX(email) {
					fmt.Printf("OK: email (%s) check success\n", res)
				} else {
					if StillAddEmail {
						fmt.Printf("Warn: email (%s) check failed\n", res)
					} else {
						fmt.Printf("Error: email (%s) check failed\n", res)
						break
					}
				}
			}

			emails = append(emails, email.Address)
		}
	}

	urls := make([]*url.URL, 0, 10)
	for {
		fmt.Printf("Enter your URL [empty to stop]: ")
		res := ReadString()
		if res == "" {
			break
		} else {
			u, err := url.Parse(res)
			if err != nil {
				fmt.Printf("Error: not a valid URL (%s)\n", err.Error())
				break
			}

			urls = append(urls, u)
		}
	}

	domainsR := make([]string, 0, 10)
	domainsRS := make([]string, 0, 10)
	ipsR := make([]net.IP, 0, 10)
	for {
		fmt.Printf("Enter your domain and it will resolve to ip [empty to stop]: ")
		res := ReadString()
		if res == "" {
			break
		} else if !utils.IsValidDomain(res) {
			fmt.Println("Error: not a valid domain")
			break
		}

		domainsR = append(domainsR, res)

		ipsN, err := utils.ResolveDomainToIPs(res)
		if err != nil {
			fmt.Printf("Error: domain resolve error (%s)\n", err.Error())
			break
		} else if ipsN == nil {
			fmt.Println("Error: domain without ip")
			break
		} else {
			fmt.Printf("Domain %s resolve result: \n", res)
			for _, i := range ipsN {
				fmt.Printf("  - %s\n", i.String())
			}
			fmt.Printf("Domain %s resolve finished.\n", res)
		}

		domainsRS = append(domainsRS, res)
		ipsR = append(ipsR, ipsN...)
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

	org, cn = sysinfo.CreateCASubjectLong(org, cn, domains, ips, emails, urls)

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

	dirPath := path.Join(home, "cert", fmt.Sprintf("Self-%s-%s-%s", cn, org, notBefore.Format("2006-01-02-15-04-05")))
	infoPath := path.Join(dirPath, "cert-info.gob")
	cert1Path := path.Join(dirPath, "cert.pem")
	cert2Path := path.Join(dirPath, "cert.cer")
	fullchain1Path := path.Join(dirPath, "fullchain.pem")
	fullchain2Path := path.Join(dirPath, "fullchain.cer")
	keyPath := path.Join(dirPath, "key.pem")

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

	err := os.MkdirAll(dirPath, 0600)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	userCert, key, certInfo, err := cert.CreateSelfCert(infoPath, cryptoType, keyLength, org, cn, domains, ips, emails, urls, ocspURLs, issurURLs, crlURLs, notBefore, notAfter)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	err = certInfo.SaveSelfCert()
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
