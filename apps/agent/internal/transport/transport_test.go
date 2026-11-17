package transport

import (
	"context"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"
)

func TestEnvelopeDecodeAndErrors(t *testing.T) {
	var hdr http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hdr = r.Header
		switch r.URL.Path {
		case "/ok":
			w.Write([]byte(`{"success":true,"statusCode":0,"message":"ok","data":{"a":1},"meta":{"requestId":"r"}}`))
		case "/bare":
			w.Write([]byte(`{"a":2}`))
		case "/err":
			w.WriteHeader(409)
			w.Write([]byte(`{"error":{"code":"TASK_EXPIRED","message":"x"},"meta":{"requestId":"r9"}}`))
		case "/noenv":
			w.WriteHeader(502)
		}
	}))
	defer srv.Close()
	c := &Client{BaseURL: srv.URL, HTTP: srv.Client()}
	var out struct{ A int }
	if err := c.Do(context.Background(), "POST", "/ok", map[string]int{"x": 1}, &out); err != nil || out.A != 1 {
		t.Fatal(err, out)
	}
	if hdr.Get("X-Agent-Protocol") != "1" || hdr.Get("Content-Type") != "application/json" ||
		!regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`).MatchString(hdr.Get("X-Request-ID")) {
		t.Fatalf("headers %v", hdr)
	}
	if err := c.Do(context.Background(), "GET", "/bare", nil, &out); err != nil || out.A != 2 {
		t.Fatal(err, out)
	}
	err := c.Do(context.Background(), "GET", "/err", nil, &out)
	if !IsStatus(err, 409) || Code(err) != "TASK_EXPIRED" {
		t.Fatalf("%v", err)
	}
	if err := c.Do(context.Background(), "GET", "/noenv", nil, nil); Code(err) != "HTTP_502" {
		t.Fatalf("%v", err)
	}
}
