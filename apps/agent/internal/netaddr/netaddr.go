// Package netaddr enumerates and classifies host IP addresses.
package netaddr

import (
	"net"
	"net/netip"
	"sort"
)

// Address matches the Center `Server.addresses[]` shape (source is always "detected").
type Address struct {
	Family    string `json:"family"` // ipv4|ipv6
	Scope     string `json:"scope"`  // public|private
	Address   string `json:"address"`
	Interface string `json:"interface"`
	Source    string `json:"source"`
}

var privatePrefixes = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),     // RFC1918
	netip.MustParsePrefix("172.16.0.0/12"),  // RFC1918
	netip.MustParsePrefix("192.168.0.0/16"), // RFC1918
	netip.MustParsePrefix("100.64.0.0/10"),  // RFC6598 CGNAT
	netip.MustParsePrefix("fc00::/7"),       // RFC4193 ULA
}

// Classify returns ("private"|"public", include). Loopback, link-local,
// multicast and unspecified addresses are excluded (include=false).
func Classify(a netip.Addr) (string, bool) {
	a = a.Unmap()
	if !a.IsValid() || a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsMulticast() ||
		a.IsUnspecified() || a.IsLinkLocalMulticast() || a.IsInterfaceLocalMulticast() {
		return "", false
	}
	for _, p := range privatePrefixes {
		if p.Contains(a) {
			return "private", true
		}
	}
	return "public", true
}

// Detect lists classified addresses on up interfaces, sorted deterministically.
func Detect() []Address {
	ifs, err := net.Interfaces()
	if err != nil {
		return []Address{}
	}
	out := []Address{}
	for _, ifc := range ifs {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip, ok := netip.AddrFromSlice(ipn.IP)
			if !ok {
				continue
			}
			ip = ip.Unmap()
			scope, ok := Classify(ip)
			if !ok {
				continue
			}
			fam := "ipv6"
			if ip.Is4() {
				fam = "ipv4"
			}
			out = append(out, Address{Family: fam, Scope: scope, Address: ip.String(), Interface: ifc.Name, Source: "detected"})
			if len(out) >= 64 {
				return out
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Interface != out[j].Interface {
			return out[i].Interface < out[j].Interface
		}
		return out[i].Address < out[j].Address
	})
	return out
}
