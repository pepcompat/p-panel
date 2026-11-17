package netaddr

import (
	"net/netip"
	"testing"
)

func TestClassify(t *testing.T) {
	cases := map[string]string{
		"10.104.0.3": "private", "172.16.5.1": "private", "172.31.255.255": "private",
		"172.32.0.1": "public", "192.168.1.1": "private", "100.64.0.1": "private",
		"100.127.255.254": "private", "100.128.0.1": "public", "8.8.8.8": "public",
		"fd00::1": "private", "fc12::1": "private", "2001:db8::1": "public",
		"::ffff:10.0.0.1": "private",
	}
	for in, want := range cases {
		got, ok := Classify(netip.MustParseAddr(in))
		if !ok || got != want {
			t.Errorf("%s: got %q ok=%v want %q", in, got, ok, want)
		}
	}
	for _, ex := range []string{"127.0.0.1", "::1", "169.254.1.1", "fe80::1", "224.0.0.1", "0.0.0.0"} {
		if _, ok := Classify(netip.MustParseAddr(ex)); ok {
			t.Errorf("%s should be excluded", ex)
		}
	}
	if Detect() == nil {
		t.Fatal("Detect must return non-nil slice")
	}
}
