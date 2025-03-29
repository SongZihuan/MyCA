// Copyright 2025 MyCA Authors. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package sysinfo

import (
	"fmt"
	"github.com/SongZihuan/MyCA/src/utils"
	"net"
	"net/url"
)

func CreateCASubject(org string, cn string) (string, string) {
	if org == "" {
		org = Hostname
	}

	if cn == "" {
		cn = fmt.Sprintf("%s%02d", Username, utils.RandIntn(98)+1) // 数字范围1-99
	}

	return org, cn
}

func CreateCASubjectLong(org string, cn string, domains []string, ips []net.IP, emails []string, urls []*url.URL) (string, string) {
	if org == "" {
		org = Hostname
	}

	if cn == "" {
		if len(domains) != 0 {
			cn = domains[0]
		} else if len(ips) != 0 {
			cn = ips[0].String()
		} else if len(emails) != 0 {
			cn = emails[0]
		} else if len(urls) != 0 {
			cn = urls[0].String()
		} else {
			cn = utils.RandStr(6 + utils.RandIntn(3)) // 6-8位随机字符串
		}
	}

	return org, cn
}
