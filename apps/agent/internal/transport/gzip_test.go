package transport

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestPostGzipAndRetryAfter(t *testing.T) {
	var gotEnc, gotType string
	var body []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotEnc, gotType = r.Header.Get("Content-Encoding"), r.Header.Get("Content-Type")
		zr, _ := gzip.NewReader(r.Body)
		body, _ = io.ReadAll(zr)
		if r.URL.Path == "/busy" {
			w.Header().Set("Retry-After", "12")
			w.WriteHeader(429)
			w.Write([]byte(`{"error":{"code":"RATE_LIMITED","message":"x"}}`))
			return
		}
		w.Write([]byte(`{"success":true,"statusCode":0,"message":"ok","data":{"accepted":1,"duplicate":false},"meta":{"requestId":"r"}}`))
	}))
	defer srv.Close()
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	zw.Write([]byte(`{"batchId":"b"}`))
	zw.Close()
	c := &Client{BaseURL: srv.URL, HTTP: srv.Client()}
	var out struct {
		Accepted int `json:"accepted"`
	}
	if err := c.PostGzip(context.Background(), "/ok", gz.Bytes(), &out); err != nil || out.Accepted != 1 {
		t.Fatal(err, out)
	}
	if gotEnc != "gzip" || gotType != "application/json" || string(body) != `{"batchId":"b"}` {
		t.Fatalf("enc=%q type=%q body=%q", gotEnc, gotType, body)
	}
	err := c.PostGzip(context.Background(), "/busy", gz.Bytes(), nil)
	var ae *APIError
	if !errors.As(err, &ae) || ae.HTTPStatus != 429 || ae.RetryAfter != 12*time.Second || ae.Code != "RATE_LIMITED" {
		t.Fatalf("%v %+v", err, ae)
	}
}

func TestParseRetryAfter(t *testing.T) {
	now := time.Date(2026, 11, 23, 10, 0, 0, 0, time.UTC)
	if ParseRetryAfter("", now) != 0 || ParseRetryAfter("-1", now) != 0 || ParseRetryAfter("x", now) != 0 {
		t.Fatal("invalid must be 0")
	}
	if ParseRetryAfter("30", now) != 30*time.Second {
		t.Fatal("seconds")
	}
	if d := ParseRetryAfter(now.Add(90*time.Second).Format(http.TimeFormat), now); d != 90*time.Second {
		t.Fatalf("date: %v", d)
	}
}
