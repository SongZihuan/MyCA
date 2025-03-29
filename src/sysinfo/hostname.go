// Copyright 2025 MyCA Authors. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package sysinfo

import (
	"fmt"
	"github.com/SongZihuan/MyCA/src/utils"
	"os"
)

var Hostname string

func init() {
	_hostname, err := os.Hostname()
	if err != nil {
		fmt.Printf("Load Hostname error: %s\n", err)
		Hostname = utils.RandStr(8)
	} else if _hostname == "" {
		fmt.Println("Load Hostname error: Hostname empty")
		Hostname = utils.RandStr(8)
	} else {
		Hostname = _hostname
	}
}
