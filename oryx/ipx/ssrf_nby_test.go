// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package ipx

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"code.dny.dev/ssrf"
)

func safe(v4, v6 []netip.Prefix, ip string) bool {
	addr := netip.MustParseAddr(ip)
	network := "tcp6"
	if addr.Is4() {
		network = "tcp4"
	}
	g := ssrf.New(ssrf.WithAnyPort(), ssrf.WithNetworks("tcp4", "tcp6"), ssrf.WithAllowedV4Prefixes(v4...), ssrf.WithAllowedV6Prefixes(v6...))
	return g.Safe(network, netip.AddrPortFrom(addr, 80).String(), nil) == nil
}

// refused reports the error ssrfDialFunc returns when the guard rejects an IP.
func refused(err error) bool {
	var opErr *net.OpError
	return errors.As(err, &opErr) && opErr.Addr == nil && opErr.Err.Error() == "no route to host"
}

// The default is a decision: change it here and in ssrf_nby.go together.
func TestDefaultAllowedPrefixes(t *testing.T) {
	want := []string{
		"10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "172.16.0.0/12",
		"192.0.0.0/24", "192.0.2.0/24", "192.31.196.0/24", "192.52.193.0/24",
		"192.88.99.0/24", "192.168.0.0/16", "192.175.48.0/24", "198.18.0.0/15",
		"198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
		"::1/128", "fc00::/7", "100::/64", "2001:db8::/32", "2620:4f:8000::/48",
	}
	if !slices.Equal(DefaultAllowedPrefixes, want) {
		t.Fatalf("default allowlist changed:\n got %q\nwant %q", DefaultAllowedPrefixes, want)
	}
}

func TestAllowedPrefixes(t *testing.T) {
	for _, tc := range []struct {
		env     string
		allowed []string
		denied  []string
	}{
		{
			env:     "",
			allowed: []string{"10.1.2.3", "100.64.0.1", "127.0.0.1", "172.16.0.1", "192.168.1.1", "198.18.215.49", "240.0.0.1", "1.1.1.1", "::1", "fd00::1"},
			denied: []string{"169.254.169.254", "0.0.0.1", "::", "fe80::1", "::ffff:a9fe:a9fe",
				"64:ff9b::a9fe:a9fe", "64:ff9b:1::a9fe:a9fe", "2002:a9fe:a9fe::1", "2001::1"},
		},
		{
			env:     "  ",
			allowed: []string{"198.18.0.1"},
			denied:  []string{"169.254.169.254"},
		},
		{
			env:     "10.0.0.0/8, fd00::/8",
			allowed: []string{"10.1.2.3", "fd00::1", "1.1.1.1"},
			denied:  []string{"198.18.0.1", "172.16.0.1", "127.0.0.1", "::1"},
		},
	} {
		v4, v6 := allowedPrefixes(tc.env)
		for _, ip := range tc.allowed {
			if !safe(v4, v6, ip) {
				t.Errorf("env %q: %s must be allowed", tc.env, ip)
			}
		}
		for _, ip := range tc.denied {
			if safe(v4, v6, ip) {
				t.Errorf("env %q: %s must be denied", tc.env, ip)
			}
		}
	}
}

func TestAllowedPrefixesInvalid(t *testing.T) {
	for _, env := range []string{"10.0.0.0/8,nope", "10.0.0.0/8,", "::ffff:198.18.0.0/111"} {
		func() {
			defer func() {
				if r := recover(); r == nil || !strings.Contains(r.(string), AllowedPrefixesEnv) {
					t.Errorf("env %q: want a panic naming %s, got %v", env, AllowedPrefixesEnv, r)
				}
			}()
			allowedPrefixes(env)
		}()
	}
}

// A rebase that drops the wiring in ssrf.go flips at least one of these.
func TestAllowInternalDialFuncUsesAllowedPrefixes(t *testing.T) {
	if os.Getenv(AllowedPrefixesEnv) != "" {
		t.Skipf("%s is set", AllowedPrefixesEnv)
	}
	for addr, wantRefused := range map[string]bool{
		"169.254.169.254:80": true,
		"198.18.0.1:9":       false,
	} {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		conn, err := AllowInternalDialFunc(ctx, "tcp", addr)
		cancel()
		if conn != nil {
			_ = conn.Close()
		}
		if refused(err) != wantRefused {
			t.Errorf("%s: want refused=%v, got %v", addr, wantRefused, err)
		}
	}
}
