// Copyright 2025 MyCA Authors. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package utils

import (
	"net"
)

func ResolveDomainToIPs(domain string) ([]net.IP, error) {
	ips, err := net.LookupHost(domain)
	if err != nil {
		return nil, err
	} else if len(ips) == 0 {
		return nil, nil
	}

	return ipStringChangeToIp(ips), nil
}

func ipStringChangeToIp(ipList []string) []net.IP {
	ips := make([]net.IP, 0, len(ipList))

	for _, ipStr := range ipList {
		if ip := net.ParseIP(ipStr); ip != nil {
			ips = append(ips, ip)
		}
	}

	return ips
}
