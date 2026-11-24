// Package provider reads cloud-provider facts (P9, contract §2). Only the
// DigitalOcean metadata service is supported: a link-local, unauthenticated
// HTTP GET with no redirects, a 2 s timeout and a 64 KiB body cap. The agent
// never infers a VPC from these facts.
package provider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"regexp"
	"time"
)

// DigitalOcean metadata defaults.
const (
	DefaultDOMetadataURL = "http://169.254.169.254/metadata/v1.json"
	MaxMetadataBytes     = 64 << 10
	MetadataTimeout      = 2 * time.Second
	maxAddrs             = 8
	maxDropletID         = 1 << 53
)

// Interfaces lists the IPv4 addresses per DigitalOcean interface type.
type Interfaces struct {
	Private []string `json:"private"`
	Public  []string `json:"public"`
}

// Info is the `provider` fact.
type Info struct {
	Name       string     `json:"name"`
	DropletID  int64      `json:"dropletId"`
	Region     string     `json:"region"`
	Interfaces Interfaces `json:"interfaces"`
}

var regionRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)

type doIface struct {
	IPv4 *struct {
		IPAddress string `json:"ip_address"`
	} `json:"ipv4"`
}

type doMetadata struct {
	DropletID  json.Number `json:"droplet_id"`
	Region     string      `json:"region"`
	Interfaces struct {
		Public  []doIface `json:"public"`
		Private []doIface `json:"private"`
	} `json:"interfaces"`
}

// ParseDOMetadata parses and validates a DigitalOcean metadata v1.json body.
// Unknown fields are ignored (the document has many); the fields used are
// validated strictly.
func ParseDOMetadata(b []byte) (*Info, error) {
	if len(b) > MaxMetadataBytes {
		return nil, errors.New("metadata larger than 64 KiB")
	}
	var m doMetadata
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("metadata: %v", err)
	}
	id, err := m.DropletID.Int64()
	if err != nil || id <= 0 || id > maxDropletID {
		return nil, errors.New("metadata: droplet_id must be a positive integer")
	}
	if !regionRe.MatchString(m.Region) {
		return nil, errors.New("metadata: invalid region")
	}
	priv, err := addrs("private", m.Interfaces.Private)
	if err != nil {
		return nil, err
	}
	pub, err := addrs("public", m.Interfaces.Public)
	if err != nil {
		return nil, err
	}
	return &Info{Name: "digitalocean", DropletID: id, Region: m.Region, Interfaces: Interfaces{Private: priv, Public: pub}}, nil
}

func addrs(kind string, ifs []doIface) ([]string, error) {
	out := []string{}
	for _, i := range ifs {
		if i.IPv4 == nil || i.IPv4.IPAddress == "" {
			continue
		}
		a, err := netip.ParseAddr(i.IPv4.IPAddress)
		if err != nil || !a.Is4() || a.String() != i.IPv4.IPAddress {
			return nil, fmt.Errorf("metadata: invalid %s ipv4 address", kind)
		}
		if len(out) >= maxAddrs {
			break
		}
		out = append(out, a.String())
	}
	return out, nil
}

// Client fetches DigitalOcean metadata.
type Client struct {
	URL  string
	HTTP *http.Client
}

// NewDO returns a metadata client for url (DefaultDOMetadataURL when empty):
// no proxy, no redirects, no keep-alive, MetadataTimeout.
func NewDO(url string) *Client {
	if url == "" {
		url = DefaultDOMetadataURL
	}
	tr := &http.Transport{Proxy: nil, DisableKeepAlives: true, ResponseHeaderTimeout: MetadataTimeout, MaxResponseHeaderBytes: 16 << 10}
	return &Client{URL: url, HTTP: &http.Client{Transport: tr, Timeout: MetadataTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

// Fetch returns the provider facts, or an error when the metadata service is
// absent, slow, redirects, answers non-200 or sends an invalid/oversized body.
func (c *Client) Fetch(ctx context.Context) (*Info, error) {
	ctx, cancel := context.WithTimeout(ctx, MetadataTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.URL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("metadata: HTTP %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, MaxMetadataBytes+1))
	if err != nil {
		return nil, err
	}
	return ParseDOMetadata(b)
}
