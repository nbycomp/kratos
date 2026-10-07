// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package ipx

import (
	"fmt"
	"net/netip"
	"os"
	"strings"
)

// AllowedPrefixesEnv holds the complete, comma-separated list of IPv4 and IPv6
// prefixes that AllowInternalDialFunc may dial, e.g. "10.0.0.0/8,fd00::/8".
// It replaces DefaultAllowedPrefixes; unset or empty keeps the default.
// An invalid prefix panics at startup.
const AllowedPrefixesEnv = "NBY_SSRF_ALLOWED_PREFIXES"

// DefaultAllowedPrefixes are the private and reserved ranges a cluster may use.
// It leaves out ranges that reach IPv4 cloud metadata (169.254.0.0/16), the
// local host (0.0.0.0/8, ::/128), the node's link (fe80::/10) or an embedded
// IPv4 address (::ffff:0:0/96, 64:ff9b::/96, 64:ff9b:1::/48, 2001::/23,
// 2002::/16). fc00::/7 still holds AWS IMDS over IPv6 (fd00:ec2::254).
// Public addresses are always allowed.
var DefaultAllowedPrefixes = []string{
	"10.0.0.0/8",        // Private-Use (RFC 1918)
	"100.64.0.0/10",     // Shared Address Space (RFC 6598)
	"127.0.0.0/8",       // Loopback (RFC 1122, Section 3.2.1.3)
	"172.16.0.0/12",     // Private-Use (RFC 1918)
	"192.0.0.0/24",      // IETF Protocol Assignments (RFC 6890, Section 2.1)
	"192.0.2.0/24",      // Documentation (TEST-NET-1) (RFC 5737)
	"192.31.196.0/24",   // AS112-v4 (RFC 7535)
	"192.52.193.0/24",   // AMT (RFC 7450)
	"192.88.99.0/24",    // Deprecated (6to4 Relay Anycast) (RFC 7526)
	"192.168.0.0/16",    // Private-Use (RFC 1918)
	"192.175.48.0/24",   // Direct Delegation AS112 Service (RFC 7534)
	"198.18.0.0/15",     // Benchmarking (RFC 2544)
	"198.51.100.0/24",   // Documentation (TEST-NET-2) (RFC 5737)
	"203.0.113.0/24",    // Documentation (TEST-NET-3) (RFC 5737)
	"224.0.0.0/4",       // Multicast (RFC 1112, Section 4)
	"240.0.0.0/4",       // Reserved (RFC 1112, Section 4)
	"::1/128",           // Loopback (RFC 4291)
	"fc00::/7",          // Unique Local (RFC 4193)
	"100::/64",          // Discard-Only (RFC 6666)
	"2001:db8::/32",     // Documentation (RFC 3849)
	"2620:4f:8000::/48", // Direct Delegation AS112 Service (RFC 7534)
}

var allowedV4Prefixes, allowedV6Prefixes = allowedPrefixes(os.Getenv(AllowedPrefixesEnv))

func allowedPrefixes(env string) (v4, v6 []netip.Prefix) {
	list := DefaultAllowedPrefixes
	if strings.TrimSpace(env) != "" {
		list = strings.Split(env, ",")
	}
	for _, s := range list {
		p, err := netip.ParsePrefix(strings.TrimSpace(s))
		if err == nil && p.Addr().Is4In6() {
			err = fmt.Errorf("%s is IPv4-mapped and never matches, use the IPv4 form", p)
		}
		if err != nil {
			panic(fmt.Sprintf("%s: %v", AllowedPrefixesEnv, err))
		}
		if p.Addr().Is4() {
			v4 = append(v4, p)
		} else {
			v6 = append(v6, p)
		}
	}
	return v4, v6
}
