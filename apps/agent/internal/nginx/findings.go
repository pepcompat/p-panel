package nginx

import (
	"sort"
	"strconv"
	"strings"
)

// Provenance points at the origin of a finding.
type Provenance struct {
	File         string   `json:"file"`
	Line         int      `json:"line"`
	IncludedFrom []string `json:"includedFrom,omitempty"`
}

// Listen is a parsed `listen` directive.
type Listen struct {
	Address       string `json:"address,omitempty"`
	Port          int    `json:"port,omitempty"`
	Unix          string `json:"unix,omitempty"`
	SSL           bool   `json:"ssl"`
	HTTP2         bool   `json:"http2"`
	DefaultServer bool   `json:"defaultServer"`
	Implicit      bool   `json:"implicit,omitempty"`
	Raw           string `json:"raw"`
}

// ServerName is a classified server_name entry.
type ServerName struct {
	Name string `json:"name"`
	Kind string `json:"kind"` // exact|wildcard|regex|catch_all
}

// Location summarises a location block.
type Location struct {
	Match       string     `json:"match"`
	Root        string     `json:"root,omitempty"`
	Alias       string     `json:"alias,omitempty"`
	ProxyPass   string     `json:"proxyPass,omitempty"`
	FastCGIPass string     `json:"fastcgiPass,omitempty"`
	Return      string     `json:"return,omitempty"`
	Provenance  Provenance `json:"provenance"`
}

// Unsupported is a directive outside the supported adoption subset.
type Unsupported struct {
	Name       string     `json:"name"`
	Context    string     `json:"context"`
	Provenance Provenance `json:"provenance"`
}

// ServerBlock is one discovered `server {}` with provenance and confidence.
type ServerBlock struct {
	ID                   string        `json:"id"`
	Context              string        `json:"context"` // http|stream
	ServerNames          []ServerName  `json:"serverNames"`
	Listen               []Listen      `json:"listen"`
	Root                 string        `json:"root,omitempty"`
	ProxyPass            []string      `json:"proxyPass"`
	FastCGIPass          []string      `json:"fastcgiPass"`
	Upstreams            []string      `json:"upstreams"`
	SSLCertificates      []string      `json:"sslCertificates"`
	SSLCertificateKeys   []string      `json:"sslCertificateKeys"`
	TLS                  bool          `json:"tls"`
	Locations            []Location    `json:"locations"`
	Includes             []string      `json:"includes"`
	Unsupported          []Unsupported `json:"unsupportedDirectives"`
	Provenance           Provenance    `json:"provenance"`
	Confidence           float64       `json:"confidence"`
	ConfidenceLevel      string        `json:"confidenceLevel"` // high|medium|low
	ManualReviewRequired bool          `json:"manualReviewRequired"`
	Reasons              []string      `json:"reasons"`
}

// Upstream is an `upstream {}` block.
type Upstream struct {
	Name       string     `json:"name"`
	Servers    []string   `json:"servers"`
	Provenance Provenance `json:"provenance"`
}

// Duplicate reports a server_name+port defined by more than one server block.
type Duplicate struct {
	Name      string   `json:"name"`
	Port      int      `json:"port"`
	ServerIDs []string `json:"serverIds"`
}

// FileInfo is a configuration file seen in the dump.
type FileInfo struct {
	Path   string `json:"path"`
	Sha256 string `json:"sha256"`
	// ShaSource is "disk" (file bytes, same as nginx.read_files/apply) or "nginx-T" (dump text fallback).
	ShaSource string `json:"shaSource,omitempty"`
}

// Report is the structured nginx discovery result.
type Report struct {
	Files       []FileInfo     `json:"files"`
	Servers     []*ServerBlock `json:"servers"`
	Upstreams   []Upstream     `json:"upstreams"`
	Duplicates  []Duplicate    `json:"duplicates"`
	Unsupported []Unsupported  `json:"unsupportedDirectives"` // outside server blocks
	Includes    []IncludeIssue `json:"includeIssues"`
}

// supported is the subset of directives the adoption engine understands.
// Everything else is reported as unsupported (conservative by design).
var supported = map[string]bool{
	"listen": true, "server_name": true, "root": true, "index": true, "location": true,
	"include": true, "try_files": true, "return": true, "error_page": true, "alias": true,
	"access_log": true, "error_log": true, "client_max_body_size": true, "charset": true,
	"add_header": true, "expires": true, "gzip": true, "gzip_types": true, "gzip_vary": true,
	"autoindex": true, "default_type": true, "deny": true, "allow": true, "keepalive_timeout": true,
	"proxy_pass": true, "proxy_set_header": true, "proxy_http_version": true, "proxy_redirect": true,
	"proxy_read_timeout": true, "proxy_connect_timeout": true, "proxy_send_timeout": true,
	"proxy_buffering": true, "proxy_buffers": true, "proxy_buffer_size": true, "proxy_cache_bypass": true,
	"proxy_hide_header": true, "proxy_intercept_errors": true, "proxy_ssl_server_name": true,
	"fastcgi_pass": true, "fastcgi_param": true, "fastcgi_index": true, "fastcgi_split_path_info": true,
	"fastcgi_read_timeout": true, "fastcgi_buffers": true, "fastcgi_buffer_size": true, "fastcgi_intercept_errors": true,
	"ssl_certificate": true, "ssl_certificate_key": true, "ssl_protocols": true, "ssl_ciphers": true,
	"ssl_prefer_server_ciphers": true, "ssl_session_cache": true, "ssl_session_timeout": true,
	"ssl_session_tickets": true, "ssl_dhparam": true, "ssl_stapling": true, "ssl_stapling_verify": true,
	"ssl_trusted_certificate": true, "ssl_ecdh_curve": true, "http2": true, "ssl": true,
	"internal": true, "log_not_found": true, "sendfile": true, "tcp_nopush": true, "tcp_nodelay": true,
	"server_tokens": true, "auth_basic": true, "auth_basic_user_file": true,
}

// serverDirectives are http-level directives that are not "unsupported" findings.
var httpLevelIgnored = map[string]bool{"server": true, "upstream": true, "include": true}

// Analyze builds a Report from a parsed config.
func Analyze(c *Config) *Report {
	r := &Report{Files: []FileInfo{}, Servers: []*ServerBlock{}, Upstreams: []Upstream{}, Duplicates: []Duplicate{}, Unsupported: []Unsupported{}, Includes: []IncludeIssue{}}
	for _, f := range c.Files {
		r.Files = append(r.Files, FileInfo{Path: f.Path, Sha256: f.Sha256})
	}
	tree, issues := c.Resolve()
	r.Includes = append(r.Includes, issues...)
	upstreamNames := map[string]bool{}
	// first pass: upstreams anywhere in http/stream
	walk(tree, "", func(d *Directive, ctx string) bool {
		if d.Name == "upstream" && d.IsBlock && len(d.Args) == 1 {
			u := Upstream{Name: d.Args[0], Servers: []string{}, Provenance: prov(d)}
			for _, s := range d.Block {
				if s.Name == "server" && len(s.Args) > 0 {
					u.Servers = append(u.Servers, s.Args[0])
				}
			}
			r.Upstreams = append(r.Upstreams, u)
			upstreamNames[u.Name] = true
			return false
		}
		return true
	})
	walk(tree, "", func(d *Directive, ctx string) bool {
		if d.Name == "server" && d.IsBlock && (ctx == "http" || ctx == "stream") {
			r.Servers = append(r.Servers, analyzeServer(d, ctx, upstreamNames, issues))
			return false
		}
		if ctx == "http" && !d.IsBlock && !httpLevelIgnored[d.Name] && isRisky(d.Name) {
			r.Unsupported = append(r.Unsupported, Unsupported{Name: d.Name, Context: ctx, Provenance: prov(d)})
		}
		if ctx == "http" && d.IsBlock && (d.Name == "map" || d.Name == "geo" || d.Name == "split_clients" || strings.Contains(d.Name, "lua")) {
			r.Unsupported = append(r.Unsupported, Unsupported{Name: d.Name, Context: ctx, Provenance: prov(d)})
			return false
		}
		return true
	})
	markDuplicates(r)
	for _, s := range r.Servers {
		score(s)
	}
	return r
}

// isRisky flags http-level directives that change request handling globally.
func isRisky(name string) bool {
	return strings.Contains(name, "lua") || strings.HasPrefix(name, "perl") || strings.HasPrefix(name, "js_") ||
		name == "rewrite" || name == "if" || name == "set" || name == "load_module"
}

func walk(ds []*Directive, ctx string, fn func(d *Directive, ctx string) bool) {
	for _, d := range ds {
		if !fn(d, ctx) {
			continue
		}
		if d.IsBlock {
			child := ctx
			if d.Name == "http" || d.Name == "stream" || d.Name == "mail" {
				child = d.Name
			}
			walk(d.Block, child, fn)
		}
	}
}

func prov(d *Directive) Provenance {
	return Provenance{File: d.File, Line: d.Line, IncludedFrom: d.IncludedFrom}
}

func analyzeServer(d *Directive, ctx string, upstreams map[string]bool, issues []IncludeIssue) *ServerBlock {
	s := &ServerBlock{
		ID: shortID(d.File + ":" + strconv.Itoa(d.Line)), Context: ctx, Provenance: prov(d),
		ServerNames: []ServerName{}, Listen: []Listen{}, ProxyPass: []string{}, FastCGIPass: []string{},
		Upstreams: []string{}, SSLCertificates: []string{}, SSLCertificateKeys: []string{},
		Locations: []Location{}, Includes: []string{}, Unsupported: []Unsupported{}, Reasons: []string{},
	}
	legacySSL := false
	var visit func(ds []*Directive, inLoc *Location, depth int)
	visit = func(ds []*Directive, inLoc *Location, depth int) {
		for _, x := range ds {
			switch x.Name {
			case "server_name":
				if inLoc == nil {
					for _, n := range x.Args {
						s.ServerNames = append(s.ServerNames, classifyName(n))
					}
				}
			case "listen":
				if inLoc == nil && len(x.Args) > 0 {
					s.Listen = append(s.Listen, parseListen(x.Args, ctx))
				}
			case "root":
				if len(x.Args) == 1 {
					if inLoc == nil {
						s.Root = x.Args[0]
					} else {
						inLoc.Root = x.Args[0]
					}
				}
			case "alias":
				if inLoc != nil && len(x.Args) == 1 {
					inLoc.Alias = x.Args[0]
				}
			case "return":
				if inLoc != nil {
					inLoc.Return = strings.Join(x.Args, " ")
				}
			case "proxy_pass":
				if len(x.Args) == 1 {
					s.ProxyPass = appendUniq(s.ProxyPass, x.Args[0])
					if u := upstreamRef(x.Args[0]); u != "" && upstreams[u] {
						s.Upstreams = appendUniq(s.Upstreams, u)
					}
					if strings.Contains(x.Args[0], "$") {
						s.Reasons = append(s.Reasons, "proxy_pass uses variables at "+x.File+":"+strconv.Itoa(x.Line))
					}
					if inLoc != nil {
						inLoc.ProxyPass = x.Args[0]
					}
				}
			case "fastcgi_pass":
				if len(x.Args) == 1 {
					s.FastCGIPass = appendUniq(s.FastCGIPass, x.Args[0])
					if upstreams[x.Args[0]] {
						s.Upstreams = appendUniq(s.Upstreams, x.Args[0])
					}
					if inLoc != nil {
						inLoc.FastCGIPass = x.Args[0]
					}
				}
			case "ssl_certificate":
				if len(x.Args) == 1 {
					s.SSLCertificates = appendUniq(s.SSLCertificates, x.Args[0])
				}
			case "ssl_certificate_key":
				if len(x.Args) == 1 {
					s.SSLCertificateKeys = appendUniq(s.SSLCertificateKeys, x.Args[0])
				}
			case "ssl":
				if len(x.Args) == 1 && x.Args[0] == "on" {
					legacySSL = true
				}
			case "include":
				if len(x.Args) == 1 {
					s.Includes = appendUniq(s.Includes, x.Args[0])
				}
			case "location":
				if x.IsBlock && depth < 8 {
					loc := Location{Match: strings.Join(x.Args, " "), Provenance: prov(x)}
					visit(x.Block, &loc, depth+1)
					s.Locations = append(s.Locations, loc)
					continue
				}
			}
			if !supported[x.Name] {
				c := "server"
				if inLoc != nil {
					c = "location"
				}
				s.Unsupported = append(s.Unsupported, Unsupported{Name: x.Name, Context: c, Provenance: prov(x)})
				// do not descend into unsupported blocks (if, *_by_lua_block, ...)
				continue
			}
			if x.IsBlock && x.Name != "location" {
				visit(x.Block, inLoc, depth+1)
			}
		}
	}
	visit(d.Block, nil, 0)
	if len(s.Listen) == 0 {
		port := 80
		s.Listen = append(s.Listen, Listen{Address: "*", Port: port, Implicit: true, Raw: "(implicit) *:80"})
	}
	for i := range s.Listen {
		if legacySSL {
			s.Listen[i].SSL = true
		}
		if s.Listen[i].SSL {
			s.TLS = true
		}
	}
	if len(s.SSLCertificates) > 0 && !s.TLS {
		s.Reasons = append(s.Reasons, "ssl_certificate set but no ssl listener")
	}
	// includes inside this server that could not be resolved
	for _, is := range issues {
		if is.File == d.File && is.Line > d.Line && within(d, is) {
			s.Reasons = append(s.Reasons, "unresolved include "+is.Pattern+" ("+is.Reason+")")
		}
	}
	return s
}

// within reports whether an include issue lies lexically inside server block d.
func within(d *Directive, is IncludeIssue) bool {
	found := false
	var w func(ds []*Directive)
	w = func(ds []*Directive) {
		for _, x := range ds {
			if x.Name == "include" && x.File == is.File && x.Line == is.Line {
				found = true
				return
			}
			if x.IsBlock {
				w(x.Block)
			}
		}
	}
	w(d.Block)
	return found
}

func classifyName(n string) ServerName {
	switch {
	case n == "_" || n == "" || n == "\"\"":
		return ServerName{Name: n, Kind: "catch_all"}
	case strings.HasPrefix(n, "~"):
		return ServerName{Name: n, Kind: "regex"}
	case strings.HasPrefix(n, "*.") || strings.HasSuffix(n, ".*") || strings.HasPrefix(n, "."):
		return ServerName{Name: n, Kind: "wildcard"}
	default:
		return ServerName{Name: strings.ToLower(n), Kind: "exact"}
	}
}

// parseListen handles `listen 80`, `listen [::]:443 ssl http2`, `listen 1.2.3.4:8080 default_server`, `listen unix:/path`.
func parseListen(args []string, ctx string) Listen {
	l := Listen{Raw: strings.Join(args, " ")}
	addr := args[0]
	switch {
	case strings.HasPrefix(addr, "unix:"):
		l.Unix = strings.TrimPrefix(addr, "unix:")
	case strings.HasPrefix(addr, "["):
		if end := strings.Index(addr, "]"); end > 0 {
			l.Address = addr[:end+1]
			if p, err := strconv.Atoi(strings.TrimPrefix(addr[end+1:], ":")); err == nil {
				l.Port = p
			} else {
				l.Port = 80
			}
		}
	default:
		if host, port, ok := strings.Cut(addr, ":"); ok {
			l.Address = host
			l.Port, _ = strconv.Atoi(port)
		} else if p, err := strconv.Atoi(addr); err == nil {
			l.Address, l.Port = "*", p
		} else {
			l.Address, l.Port = addr, 80
		}
	}
	for _, a := range args[1:] {
		switch {
		case a == "ssl":
			l.SSL = true
		case a == "http2":
			l.HTTP2 = true
		case a == "default_server" || a == "default":
			l.DefaultServer = true
		}
	}
	_ = ctx
	return l
}

func upstreamRef(target string) string {
	for _, p := range []string{"http://", "https://", "grpc://", "grpcs://"} {
		if strings.HasPrefix(target, p) {
			rest := strings.TrimPrefix(target, p)
			if i := strings.IndexAny(rest, "/:"); i >= 0 {
				rest = rest[:i]
			}
			return rest
		}
	}
	return target // stream proxy_pass name
}

func markDuplicates(r *Report) {
	type key struct {
		name string
		port int
	}
	m := map[key][]string{}
	for _, s := range r.Servers {
		ports := map[int]bool{}
		for _, l := range s.Listen {
			if l.Port > 0 {
				ports[l.Port] = true
			}
		}
		for _, n := range s.ServerNames {
			if n.Kind == "catch_all" {
				continue
			}
			for p := range ports {
				k := key{n.Name, p}
				m[k] = appendUniq(m[k], s.ID)
			}
		}
	}
	byID := map[string]*ServerBlock{}
	for _, s := range r.Servers {
		byID[s.ID] = s
	}
	for k, ids := range m {
		if len(ids) < 2 {
			continue
		}
		sort.Strings(ids)
		r.Duplicates = append(r.Duplicates, Duplicate{Name: k.name, Port: k.port, ServerIDs: ids})
		for _, id := range ids {
			byID[id].Reasons = append(byID[id].Reasons, "duplicate server_name "+k.name+" on port "+strconv.Itoa(k.port))
		}
	}
	sort.Slice(r.Duplicates, func(i, j int) bool {
		if r.Duplicates[i].Name != r.Duplicates[j].Name {
			return r.Duplicates[i].Name < r.Duplicates[j].Name
		}
		return r.Duplicates[i].Port < r.Duplicates[j].Port
	})
}

// score assigns confidence: how sure we are this block maps cleanly to a site.
func score(s *ServerBlock) {
	c := 1.0
	exact := 0
	for _, n := range s.ServerNames {
		switch n.Kind {
		case "exact":
			exact++
		case "wildcard":
			c -= 0.1
		case "regex":
			c -= 0.2
		}
	}
	if exact == 0 {
		c -= 0.2
		s.Reasons = append(s.Reasons, "no exact server_name")
	}
	if len(s.Unsupported) > 0 {
		c -= 0.3
		names := []string{}
		for _, u := range s.Unsupported {
			names = appendUniq(names, u.Name)
		}
		s.Reasons = append(s.Reasons, "unsupported directives: "+strings.Join(names, ","))
	}
	for _, r := range s.Reasons {
		switch {
		case strings.HasPrefix(r, "duplicate"):
			c -= 0.3
		case strings.HasPrefix(r, "proxy_pass uses variables"), strings.HasPrefix(r, "unresolved include"):
			c -= 0.2
		}
	}
	if s.Root == "" && len(s.ProxyPass) == 0 && len(s.FastCGIPass) == 0 {
		hasLocRoot := false
		for _, l := range s.Locations {
			if l.Root != "" || l.Alias != "" || l.Return != "" {
				hasLocRoot = true
			}
		}
		if !hasLocRoot {
			c -= 0.1
			s.Reasons = append(s.Reasons, "no root/proxy_pass/fastcgi_pass target")
		}
	}
	if c < 0 {
		c = 0
	}
	s.Confidence = float64(int(c*100+0.5)) / 100
	switch {
	case s.Confidence >= 0.8:
		s.ConfidenceLevel = "high"
	case s.Confidence >= 0.5:
		s.ConfidenceLevel = "medium"
	default:
		s.ConfidenceLevel = "low"
	}
	for _, r := range s.Reasons {
		if strings.HasPrefix(r, "duplicate") || strings.HasPrefix(r, "unsupported") || strings.HasPrefix(r, "unresolved") || strings.HasPrefix(r, "proxy_pass uses") {
			s.ManualReviewRequired = true
		}
	}
	if s.ConfidenceLevel == "low" {
		s.ManualReviewRequired = true
	}
}

func appendUniq(s []string, v string) []string {
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}

func shortID(s string) string { return "srv_" + sum(s)[:12] }

// ParseAndAnalyze is the convenience entry point for `nginx -T` output.
func ParseAndAnalyze(dump, defaultFile string) (*Report, error) {
	c, err := ParseDump(dump, defaultFile)
	if err != nil {
		return nil, err
	}
	return Analyze(c), nil
}
