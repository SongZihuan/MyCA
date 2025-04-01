// Copyright 2025 MyCA Authors. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package utils

import "strings"

func CopySlice[T any](src []T) []T {
	dest := make([]T, len(src))
	copy(dest, src)
	return dest
}

func CleanStringSlice(lst []string) []string {
	res := make([]string, 0, len(lst))

	for _, l := range lst {
		if str := strings.TrimSpace(l); str != "" {
			res = append(res, str)
		}
	}

	return res
}
