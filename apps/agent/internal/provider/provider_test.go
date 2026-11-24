package provider

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"
)

const sample = `{"droplet_id":2756294,"hostname":"node-a","vendor_data":"x","public_keys":[],"region":"lab1",
 "interfaces":{"public":[{"ipv4":{"ip_address":"203.0.113.10","netmask":"255.255.240.0","gateway":"203.0.113.1"},"mac":"aa","type":"public"}],
 "private":[{"ipv4":{"ip_address":"10.110.0.11","netmask":"255.255.0.0","gateway":"0.0.0.0"},"mac":"bb","type":"private"}]},
 "floating_ip":{"ipv4":{"active":false}},"dns":{"nameservers":["1.1.1.1"]}}`

func TestParseDOMetadata(t *testing.T) {
	in, err := ParseDOMetadata([]byte(sample))
	if err != nil {
		t.Fatal(err)
	}
	if in.Name != "digitalocean" || in.DropletID != 2756294 || in.Region != "lab1" ||
		len(in.Interfaces.Private) != 1 || in.Interfaces.Private[0] != "10.110.0.11" || in.Interfaces.Public[0] != "203.0.113.10" {
		t.Fatalf("%+v", in)
	}
	noPriv, err := ParseDOMetadata([]byte(`{"droplet_id":1,"region":"nyc3","interfaces":{"public":[{"ipv4":{"ip_address":"203.0.113.9"}}]}}`))
	if err != nil || noPriv.Interfaces.Private == nil || len(noPriv.Interfaces.Private) != 0 {
		t.Fatalf("%+v %v", noPriv, err)
	}
	for _, bad := range []string{
		`{}`, `{"droplet_id":0,"region":"nyc3"}`, `{"droplet_id":-1,"region":"nyc3"}`, `{"droplet_id":1.5,"region":"nyc3"}`,
		`{"droplet_id":1,"region":"NYC 3"}`, `{"droplet_id":1,"region":""}`,
		`{"droplet_id":1,"region":"nyc3","interfaces":{"private":[{"ipv4":{"ip_address":"10.0.0.1/24"}}]}}`,
		`{"droplet_id":1,"region":"nyc3","interfaces":{"private":[{"ipv4":{"ip_address":"fd00::1"}}]}}`,
		`{"droplet_id":1,"region":"nyc3","interfaces":{"private":[{"ipv4":{"ip_address":"010.0.0.1"}}]}}`,
		`not json`, `{"droplet_id":9007199254740993,"region":"nyc3"}`,
	} {
		if _, err := ParseDOMetadata([]byte(bad)); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
	if _, err := ParseDOMetadata([]byte(`{"droplet_id":1,"region":"nyc3","pad":"` + strings.Repeat("x", MaxMetadataBytes) + `"}`)); err == nil {
		t.Fatal("oversized accepted")
	}
}

func TestFetchNoRedirectsTimeoutAndCap(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/ok", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(sample)) })
	mux.HandleFunc("/redirect", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/ok", http.StatusFound) })
	mux.HandleFunc("/big", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"droplet_id":1,"region":"nyc3","pad":"` + strings.Repeat("x", MaxMetadataBytes+10) + `"}`))
	})
	mux.HandleFunc("/slow", func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(5 * time.Second):
		case <-r.Context().Done():
		}
	})
	mux.HandleFunc("/404", http.NotFound)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	ctx := context.Background()
	if in, err := NewDO(srv.URL + "/ok").Fetch(ctx); err != nil || in.Region != "lab1" {
		t.Fatalf("%+v %v", in, err)
	}
	for _, p := range []string{"/redirect", "/big", "/404"} {
		if _, err := NewDO(srv.URL + p).Fetch(ctx); err == nil {
			t.Errorf("%s accepted", p)
		}
	}
	start := time.Now()
	if _, err := NewDO(srv.URL + "/slow").Fetch(ctx); err == nil || time.Since(start) > 3*time.Second {
		t.Fatalf("slow: %v after %s", err, time.Since(start))
	}
	if NewDO("").URL != DefaultDOMetadataURL {
		t.Fatal("default url")
	}
	if a := netip.MustParseAddr("169.254.169.254"); !a.IsLinkLocalUnicast() {
		t.Fatal("default metadata address must be link-local")
	}
}

func FuzzParseDOMetadata(f *testing.F) {
	f.Add([]byte(sample))
	f.Add([]byte(`{"droplet_id":"12","region":"x"}`))
	f.Add([]byte(`{"droplet_id":1,"region":"a","interfaces":{"private":[{"ipv4":null},{"ipv4":{"ip_address":"1.2.3.4"}}]}}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		in, err := ParseDOMetadata(b)
		if err != nil {
			return
		}
		if in.DropletID <= 0 || in.DropletID > maxDropletID || !regionRe.MatchString(in.Region) || in.Name != "digitalocean" {
			t.Fatalf("accepted %+v", in)
		}
		for _, l := range [][]string{in.Interfaces.Private, in.Interfaces.Public} {
			if l == nil || len(l) > maxAddrs {
				t.Fatalf("list %v", l)
			}
			for _, a := range l {
				if p, err := netip.ParseAddr(a); err != nil || !p.Is4() {
					t.Fatalf("addr %q", a)
				}
			}
		}
	})
}
