// Copyright 2025 MyCA Authors. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

// Package global 包含证书方面的信息
package global

import (
	"crypto/x509/pkix"
	"fmt"
	"github.com/SongZihuan/MyCA/src/sysinfo"
	"github.com/SongZihuan/MyCA/src/utils"
	"net"
	"net/url"
	"strings"
	"unicode"
)

type CertSubject struct {
	C  []string // 国家（仅限2字母大写）
	ST []string // 省份
	L  []string // 城市
	O  []string // 组织
	OU []string // 组织单位
	SA []string // 街道
	PC []string // 邮编
	CN string   // 名称

	ItemList []string
	ItemMap  map[string]string
}

func NewCertSubject() *CertSubject {
	return &CertSubject{
		ItemList: make([]string, 0, 6),
		ItemMap:  make(map[string]string, 6),
	}
}

func (c *CertSubject) Set(name string, value []string) error {
	name = strings.ToUpper(name)

	if value == nil {
		value = make([]string, 0, 0)
	}

	value = utils.CleanStringSlice(value)

	switch name {
	case "C":
		if len(value) == 0 || c.checkCountryList(value) {
			c.C = utils.CopySlice(value)
			break
		}
		return fmt.Errorf("not a valid country name")
	case "ST":
		c.ST = utils.CopySlice(value)
	case "L":
		c.L = utils.CopySlice(value)
	case "O":
		c.O = utils.CopySlice(value)
	case "OU":
		c.OU = utils.CopySlice(value)
	case "SA":
		c.SA = utils.CopySlice(value)
	case "PC":
		c.PC = utils.CopySlice(value)
	case "CN":
		if len(value) == 0 {
			c.CN = ""
		} else if len(value) == 1 {
			c.CN = value[0]
		} else {
			return fmt.Errorf("too many CN")
		}
	default:
		return fmt.Errorf("not a valid nname: %s", name)
	}

	if len(value) != 0 && value[0] != "" {
		c.ItemList = append(c.ItemList, value[0])
		c.ItemMap[name] = value[0]
	}

	return nil
}

func (c *CertSubject) checkCountryList(countryList []string) bool {
	for _, country := range countryList {
		if !c.checkCountry(country) {
			return false
		}
	}
	return true
}

func (c *CertSubject) checkCountry(country string) bool {
	return len(country) == 2 && unicode.IsUpper(rune(country[0])) && unicode.IsUpper(rune(country[1]))
}

func (c *CertSubject) SetCNIfEmpty(args ...any) error {
	if c.CN != "" {
		return nil
	} else if len(args) == 0 {
		c.CN = fmt.Sprintf("%s-%02d", sysinfo.Username, utils.RandIntn(98)+1) // 数字范围1-99
	} else if len(args) == 4 {
		domains, ok1 := args[0].([]string)
		ips, ok2 := args[1].([]net.IP)
		emails, ok3 := args[3].([]string)
		urls, ok4 := args[4].([]*url.URL)

		if !ok1 || !ok2 || !ok3 || !ok4 {
			return fmt.Errorf("args error")
		}

		if len(domains) != 0 {
			c.CN = domains[0]
		} else if len(ips) != 0 {
			c.CN = ips[0].String()
		} else if len(emails) != 0 {
			c.CN = emails[0]
		} else if len(urls) != 0 {
			c.CN = urls[0].String()
		} else {
			c.CN = utils.RandStr(6 + utils.RandIntn(3)) // 6-8位随机字符串
		}
	} else {
		return fmt.Errorf("args error")
	}

	return nil
}

func (c *CertSubject) ToPkixName() pkix.Name {
	return pkix.Name{
		Country:            utils.CopySlice(c.C),
		Organization:       utils.CopySlice(c.C),
		OrganizationalUnit: utils.CopySlice(c.C),
		Locality:           utils.CopySlice(c.C),
		Province:           utils.CopySlice(c.C),
		StreetAddress:      utils.CopySlice(c.C),
		PostalCode:         utils.CopySlice(c.C),
		CommonName:         c.CN,
		SerialNumber:       "", // 与证书的`SerialNumber`不同，默认可以不设置
	}
}
