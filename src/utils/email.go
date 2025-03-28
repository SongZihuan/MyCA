// Copyright 2025 MyCA Authors. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package utils

import (
	"net"
	"net/mail"
	"strings"
)

func CheckEmailMX(email *mail.Address) bool {
	emailSplit := strings.Split(email.Address, "@")
	if len(emailSplit) != 2 {
		return false
	}

	// 查询MX记录
	mxRecords, err := net.LookupMX(emailSplit[1])

	return err == nil && len(mxRecords) != 0
}
