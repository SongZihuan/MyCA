// Copyright 2025 MyCA Authors. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package sysinfo

import (
	"github.com/SongZihuan/MyCA/src/utils"
	"os/user"
)

var Username string

func init() {
	currentUser, err := user.Current()
	if err != nil {
		Username = utils.RandStr(6 + utils.RandIntn(3))
	} else if currentUser.Name != "" {
		Username = currentUser.Name
	} else if currentUser.Username != "" {
		Username = currentUser.Username
	} else {
		Username = utils.RandStr(6 + utils.RandIntn(3))
	}
}
