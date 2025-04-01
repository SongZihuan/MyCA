package mycav1

import (
	"crypto/x509"
	"errors"
	"fmt"
	"github.com/SongZihuan/MyCA/src/global"
	"github.com/SongZihuan/MyCA/src/sysinfo"
	"github.com/SongZihuan/MyCA/src/utils"
	"golang.org/x/term"
	"os"
	"path"
	"strconv"
	"strings"
	"time"
)

func ReadNumber() int {
	if stdinReader == nil {
		fmt.Println("Error: stdinReader is nil")
		return 0
	}

	input, err := stdinReader.ReadString('\n')
	if err != nil {
		fmt.Printf("Error: %s\n", err.Error())
		return 0
	}

	input = strings.TrimSuffix(input, "\n")
	input = strings.TrimSpace(input)

	if input == "" {
		return 0
	}

	m, err := strconv.ParseInt(input, 10, 64)
	if err != nil {
		fmt.Printf("Error: %s\n", err.Error())
		return 0
	}

	return int(m)
}

func ReadString() string {
	if stdinReader == nil {
		fmt.Println("Error: stdinReader is nil")
		return ""
	}

	input, err := stdinReader.ReadString('\n')
	if err != nil {
		fmt.Printf("Error: %s\n", err.Error())
		return ""
	}

	input = strings.TrimSuffix(input, "\n")
	input = strings.TrimSpace(input)

	return input
}

func ReadPassword() string {
	state, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		return ReadString()
	}
	defer func() {
		_ = term.Restore(int(os.Stdin.Fd()), state)
		fmt.Printf("\n")
	}()

	fmt.Printf("[note: the password you type will not be echoed] ")
	pw, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		fmt.Printf("Error: %s\n", err.Error())
	}

	password := string(pw)
	password = strings.TrimSuffix(password, "\n")
	password = strings.TrimSpace(password)

	return password
}

func ReadTimeDuration(defaultVal time.Duration) time.Duration {
	input := ReadString()
	if input == "" {
		return defaultVal
	}

	res := utils.ReadTimeDuration(input)
	if res == 0 {
		return defaultVal
	}

	return res
}

func ReadBoolDefaultYesPrint() bool {
	fmt.Printf(" [default=yes/no] ")
	return ReadBoolDefaultYes()
}

func ReadBoolDefaultYes() bool {
	input := strings.ToLower(ReadString())
	return input != "n" && input != "no" && input != "not" && input != "stop"
}

func ReadBoolDefaultNoPrint() bool {
	fmt.Printf(" [yes/default=no] ")
	return ReadBoolDefaultNo()
}

func ReadBoolDefaultNo() bool {
	input := strings.ToLower(ReadString())
	return input == "yes" || input == "y" || input == "ok"
}

func ReadSubject() (*global.CertSubject, error) {
	res := global.NewCertSubject()

	err := res.Set("C", ReadMoreString("Enter the country name [only two capital letters]"))
	if err != nil {
		return nil, err
	}

	err = res.Set("ST", ReadMoreString("Enter the Province or State"))
	if err != nil {
		return nil, err
	}

	err = res.Set("L", ReadMoreString("Enter the City"))
	if err != nil {
		return nil, err
	}

	_o := ReadMoreString("Enter the Organization or Company name")
	if len(_o) != 0 {
		err = res.Set("O", _o)
		if err != nil {
			return nil, err
		}
	} else if sysinfo.Hostname != "" {
		fmt.Printf("Do you want to use the hostname (%s) to be the organization or company name?", sysinfo.Hostname)
		if ReadBoolDefaultYesPrint() {
			err = res.Set("O", []string{sysinfo.Hostname})
			if err != nil {
				return nil, err
			}
		}
	}

	err = res.Set("SA", ReadMoreString("Enter the StreetAddress"))
	if err != nil {
		return nil, err
	}

	err = res.Set("PC", ReadMoreString("Enter the PostalCode"))
	if err != nil {
		return nil, err
	}

	fmt.Printf("Enter the common name: ")
	_cn := ReadString()
	if _cn != "" {
		err = res.Set("CN", []string{_cn})
		if err != nil {
			return nil, err
		}
	} else if sysinfo.Username != "" {
		fmt.Printf("Do you want to use the username (%s) to be the common name?", sysinfo.Username)
		if ReadBoolDefaultYesPrint() {
			err = res.Set("CN", []string{sysinfo.Username})
			if err != nil {
				return nil, err
			}
		}
	}

	return res, nil
}

func processDirName(name string) string {
	for _, k := range " \t@#$￥&()|\\/:*?\"<>" {
		name = strings.Replace(name, string(k), "", -1) // 删除错误字符
	}

	name = strings.TrimRight(name, ".")
	return name
}

func processAllDefaultName(name1, name2, name3, name4 string) (string, string, string, string) {
	return processDirName(name1),
		processDirName(name2),
		processDirName(name3),
		processDirName(name4)
}

func ReadDir(basePath string, defaultPrefix string, subject *global.CertSubject) (string, string, error) {
	if subject.CN == "" {
		return "", "", fmt.Errorf("not common name")
	}

	fmt.Printf("The files are stored in: %s\n", basePath)
	showFileOnPath(basePath)

	name1 := fmt.Sprintf("%s%s", defaultPrefix, strings.Join(subject.ItemList, "-"))
	name2 := fmt.Sprintf("%s", strings.Join(subject.ItemList, "-"))
	name3 := fmt.Sprintf("%s%s", defaultPrefix, subject.CN)
	name4 := fmt.Sprintf("%s", subject.CN)

	name1, name2, name3, name4 = processAllDefaultName(name1, name2, name3, name4)

	if !utils.IsValidFilename(name1) || !utils.IsValidFilename(name2) || !utils.IsValidFilename(name3) || !utils.IsValidFilename(name4) {
		return "", "", fmt.Errorf("bad default name: bad subject")
	}

	fmt.Printf(`Here are some default file names:
1) %s
2) %s
3) %s
4) %s
5/other) Customize a file name
Please choose a name: `, name1, name2, name3, name4)
	nameChoose := ReadNumber()
	switch nameChoose {
	case 1:
		return name1, path.Join(basePath, name1), nil
	case 2:
		return name2, path.Join(basePath, name2), nil
	case 3:
		return name3, path.Join(basePath, name3), nil
	case 4:
		return name4, path.Join(basePath, name4), nil
	}

	fmt.Printf("Please enter your custom name: ")
	name := ReadString()

	if utils.IsValidFilename(name) {
		return name, path.Join(basePath, name), nil
	}

	fmt.Printf("The name you enter is not valid, Do you need us to edit it?")
	if ReadBoolDefaultYesPrint() {
		nameAfterEdit := processDirName(name)
		if utils.IsValidFilename(nameAfterEdit) {
			fmt.Printf("The new name (%s) is valid, Are you sure you want to use it?")
			if ReadBoolDefaultYesPrint() {
				return nameAfterEdit, path.Join(basePath, nameAfterEdit), nil
			}
			return "", "", fmt.Errorf("not a valid name")
		}
		fmt.Printf("Sorry, edit failed.")
		return "", "", fmt.Errorf("not a valid name")
	}

	return "", "", fmt.Errorf("not a valid name")
}

type Warning struct {
	Msg string
}

func NewWarning(msg string) *Warning {
	return &Warning{
		Msg: msg,
	}
}

func NewWarningF(format string, args ...any) *Warning {
	return NewWarning(fmt.Sprintf(format, args...))
}

func (w *Warning) Error() string {
	return w.Msg
}

func ReadMoreString(tips string) []string {
	resList := make([]string, 0, 10)

	for {
		fmt.Printf("%s [empty to stop]: ", tips)
		res := ReadString()
		if res == "" {
			break
		}
		resList = append(resList, res)
	}

	return resList
}

func ReadMoreStringWithPolicy[T any](tips string, checker func(string) (T, error)) ([]T, error) {
	resList := make([]T, 0, 10)

	for {
		fmt.Printf("%s [empty to stop]: ", tips)
		res := ReadString()
		if res == "" {
			break
		} else {
			newRes, err := checker(res)
			if err != nil {
				var warn *Warning
				if errors.As(err, &warn) {
					fmt.Printf("Error: %s\n", warn.Error())
				} else {
					return nil, err
				}
			} else {
				resList = append(resList, newRes)
			}
		}
	}

	return resList, nil
}

func ReadMoreStringWithProcess(tips string, checker func(string) error) error {
	for {
		fmt.Printf("%s [empty to stop]: ", tips)
		res := ReadString()
		if res == "" {
			break
		} else {
			err := checker(res)
			if err != nil {
				var warn *Warning
				if errors.As(err, &warn) {
					fmt.Printf("Error: %s\n", warn.Error())
				} else {
					return err
				}
			}
		}
	}

	return nil
}

func ReadMoreNumberWithPolicy[T any](tips string, checker func(int) (T, error)) ([]T, error) {
	resList := make([]T, 0, 10)

	for {
		fmt.Printf("%s [zero to stop]: ", tips)
		res := ReadNumber()
		if res == 0 {
			break
		} else {
			newRes, err := checker(res)
			if err != nil {
				var warn *Warning
				if errors.As(err, &warn) {
					fmt.Printf("Error: %s\n", warn.Error())
				} else {
					return nil, err
				}
			} else {
				resList = append(resList, newRes)
			}
		}
	}

	return resList, nil
}

var KeyUsageList = []x509.KeyUsage{
	x509.KeyUsageDigitalSignature,  // 数字签名
	x509.KeyUsageContentCommitment, // 公钥可加密数据
	x509.KeyUsageKeyEncipherment,   // 加密密钥 （RSA交换）
	x509.KeyUsageDataEncipherment,  // 公钥可解密数据
	x509.KeyUsageKeyAgreement,      // 可用于密钥协商
	x509.KeyUsageCertSign,          // 签发证书
	x509.KeyUsageCRLSign,           // 签发CRL
}

var KeyUsageMap = map[x509.KeyUsage]string{
	x509.KeyUsageDigitalSignature:  "KeyUsageDigitalSignature",
	x509.KeyUsageContentCommitment: "KeyUsageContentCommitment",
	x509.KeyUsageKeyEncipherment:   "KeyUsageKeyEncipherment",
	x509.KeyUsageDataEncipherment:  "KeyUsageDataEncipherment",
	x509.KeyUsageKeyAgreement:      "KeyUsageKeyAgreement",
	x509.KeyUsageCertSign:          "KeyUsageCertSign",
	x509.KeyUsageCRLSign:           "KeyUsageCRLSign",
}

func ReadKeyUsage(certType string) (x509.KeyUsage, error) {
	var res x509.KeyUsage
	var addRecord = make(map[x509.KeyUsage]bool, len(KeyUsageList))

	fmt.Printf("Now we should setting the key usage.")

	switch strings.ToLower(certType) {
	case "ica":
		fallthrough
	case "rca":
		fmt.Printf("Do you want to add the default key usage (KeyUsageCertSign and KeyUsageCRLSign) ?")
	case "new_cert":
		fmt.Printf("Do you want to add the default key usage (KeyUsageDigitalSignature) ?")
	case "old_cert":
		fmt.Printf("Do you want to add the default key usage (KeyUsageKeyEncipherment) ?")
	case "auto_cert":
		fmt.Printf("Do you want to add the default key usage (KeyUsageDigitalSignature or KeyUsageKeyEncipherment) ?")
	case "cert":
		fmt.Printf("Do you want to add the default key usage (KeyUsageDigitalSignature and KeyUsageKeyEncipherment) ?")
	}

	if ReadBoolDefaultYesPrint() {
		switch strings.ToLower(certType) {
		case "ica":
			fallthrough
		case "rca":
			fmt.Println("The KeyUsageCertSign and KeyUsageCRLSign be choose.")
			res |= x509.KeyUsageCertSign
			res |= x509.KeyUsageCRLSign

			addRecord[x509.KeyUsageCertSign] = true
			addRecord[x509.KeyUsageCRLSign] = true
		case "new_cert":
			fmt.Println("The KeyUsageDigitalSignature be choose.")
			res |= x509.KeyUsageDigitalSignature

			addRecord[x509.KeyUsageDigitalSignature] = true
		case "old_cert":
			fmt.Println("The KeyUsageKeyEncipherment must be choose.")
			res |= x509.KeyUsageKeyEncipherment

			addRecord[x509.KeyUsageKeyEncipherment] = true
		case "auto_cert":
			fmt.Printf("What kind of certificate do you want to generate? Newer (with key exchange) / Older (with key encryption) / Both? [default=both/newer/older]: ")
			switch strings.ToLower(ReadString()) {
			case "n":
				fallthrough
			case "new":
				fallthrough
			case "newer":
				fmt.Println("The KeyUsageDigitalSignature be choose.")
				res |= x509.KeyUsageDigitalSignature

				addRecord[x509.KeyUsageDigitalSignature] = true
			case "o":
				fallthrough
			case "old":
				fallthrough
			case "older":
				fmt.Println("The KeyUsageKeyEncipherment be choose.")
				res |= x509.KeyUsageKeyEncipherment

				addRecord[x509.KeyUsageKeyEncipherment] = true
			case "b":
				fallthrough
			case "both":
				fallthrough
			default:
				fmt.Println("The KeyUsageDigitalSignature and KeyUsageKeyEncipherment be choose.")
				res |= x509.KeyUsageDigitalSignature
				res |= x509.KeyUsageKeyEncipherment

				addRecord[x509.KeyUsageDigitalSignature] = true
				addRecord[x509.KeyUsageKeyEncipherment] = true
			}
		case "cert":
			fmt.Println("The KeyUsageDigitalSignature and KeyUsageKeyEncipherment be choose.")
			res |= x509.KeyUsageDigitalSignature
			res |= x509.KeyUsageKeyEncipherment

			addRecord[x509.KeyUsageDigitalSignature] = true
			addRecord[x509.KeyUsageKeyEncipherment] = true
		}
	}

	fmt.Printf("There will show the other Key Usage that you can add to you cert: \n")
	for i, usage := range KeyUsageList {
		fmt.Printf(" %d %s\n", i+1, KeyUsageMap[usage])
	}

	_, err := ReadMoreNumberWithPolicy("Choose the other KeyUsage", func(i int) (x509.KeyUsage, error) {
		index := i - 1

		if index < 0 || index >= len(KeyUsageList) {
			return 0, NewWarning("invalid number")
		}

		usage := KeyUsageList[index]

		if yes, ok := addRecord[usage]; ok && yes {
			return 0, NewWarning("Please do not enter repeatedly")
		}

		res |= usage
		addRecord[usage] = true

		return usage, nil
	})
	if err != nil {
		return 0, err
	}

	fmt.Printf("The key usage you add: \n")
	for usage, yes := range addRecord {
		if yes {
			fmt.Printf(" %s\n", KeyUsageMap[usage])
		}
	}

	return res, nil
}

var ExtKeyUsageList = []x509.ExtKeyUsage{
	x509.ExtKeyUsageAny,
	x509.ExtKeyUsageServerAuth,
	x509.ExtKeyUsageClientAuth,
	x509.ExtKeyUsageCodeSigning,
	x509.ExtKeyUsageEmailProtection,
	x509.ExtKeyUsageIPSECEndSystem,
	x509.ExtKeyUsageIPSECTunnel,
	x509.ExtKeyUsageIPSECUser,
	x509.ExtKeyUsageTimeStamping,
	x509.ExtKeyUsageOCSPSigning,
	x509.ExtKeyUsageMicrosoftServerGatedCrypto,
	x509.ExtKeyUsageNetscapeServerGatedCrypto,
	x509.ExtKeyUsageMicrosoftCommercialCodeSigning,
	x509.ExtKeyUsageMicrosoftKernelCodeSigning,
}

var ExtKeyUsageMap = map[x509.ExtKeyUsage]string{
	x509.ExtKeyUsageAny:                            "ExtKeyUsageAny",
	x509.ExtKeyUsageServerAuth:                     "ExtKeyUsageServerAuth",
	x509.ExtKeyUsageClientAuth:                     "ExtKeyUsageClientAuth",
	x509.ExtKeyUsageCodeSigning:                    "ExtKeyUsageCodeSigning",
	x509.ExtKeyUsageEmailProtection:                "ExtKeyUsageEmailProtection",
	x509.ExtKeyUsageIPSECEndSystem:                 "ExtKeyUsageIPSECEndSystem",
	x509.ExtKeyUsageIPSECTunnel:                    "ExtKeyUsageIPSECTunnel",
	x509.ExtKeyUsageIPSECUser:                      "ExtKeyUsageIPSECUser",
	x509.ExtKeyUsageTimeStamping:                   "ExtKeyUsageTimeStamping",
	x509.ExtKeyUsageOCSPSigning:                    "ExtKeyUsageOCSPSigning",
	x509.ExtKeyUsageMicrosoftServerGatedCrypto:     "ExtKeyUsageMicrosoftServerGatedCrypto",
	x509.ExtKeyUsageNetscapeServerGatedCrypto:      "ExtKeyUsageNetscapeServerGatedCrypto",
	x509.ExtKeyUsageMicrosoftCommercialCodeSigning: "ExtKeyUsageMicrosoftCommercialCodeSigning",
	x509.ExtKeyUsageMicrosoftKernelCodeSigning:     "ExtKeyUsageMicrosoftKernelCodeSigning",
}

func ReadExtKeyUsage() ([]x509.ExtKeyUsage, error) {
	var res = make([]x509.ExtKeyUsage, 0, len(ExtKeyUsageList))
	var addRecord = make(map[x509.ExtKeyUsage]bool, len(ExtKeyUsageList))

	fmt.Printf("Dou you want to add extUsage? [default=all/no/choose]: ")
	switch strings.ToLower(ReadString()) {
	case "n":
		fallthrough
	case "no":
		return make([]x509.ExtKeyUsage, 0, 0), nil
	case "all":
		fallthrough
	case "a":
		fallthrough
	default:
		return utils.CopySlice(ExtKeyUsageList), nil
	case "choose":
		fallthrough
	case "c":
		// pass
	}

	fmt.Printf("There will show the Ext Key Usage that you can add to you cert: \n")
	for i, usage := range ExtKeyUsageList {
		fmt.Printf(" %d %s\n", i+1, ExtKeyUsageMap[usage])
	}

	_, err := ReadMoreNumberWithPolicy("Choose the other ExtKeyUsage", func(i int) (x509.ExtKeyUsage, error) {
		index := i - 1

		if index < 0 || index >= len(ExtKeyUsageList) {
			return 0, NewWarning("invalid number")
		}

		extUsage := ExtKeyUsageList[index]

		if yes, ok := addRecord[extUsage]; ok && yes {
			return 0, NewWarning("Please do not enter repeatedly")
		}

		res = append(res, extUsage)
		addRecord[extUsage] = true

		return extUsage, nil
	})
	if err != nil {
		return nil, err
	}

	fmt.Printf("The ext key usage you add: \n")
	for extUsage, yes := range addRecord {
		if yes {
			fmt.Printf(" %s\n", ExtKeyUsageMap[extUsage])
		}
	}

	return res, nil
}
