package nginx

import (
	"crypto/sha256"
	"encoding/hex"
	"path"
	"sort"
	"strings"
)

// Directive is one nginx directive; Block is non-nil for block directives.
type Directive struct {
	Name    string       `json:"name"`
	Args    []string     `json:"args,omitempty"`
	Block   []*Directive `json:"block,omitempty"`
	IsBlock bool         `json:"isBlock,omitempty"`
	File    string       `json:"file"`
	Line    int          `json:"line"`
	// IncludedFrom is the include chain ("file:line") that pulled this directive in.
	IncludedFrom []string `json:"includedFrom,omitempty"`
}

// File is one parsed configuration file.
type File struct {
	Path       string       `json:"path"`
	Sha256     string       `json:"sha256"`
	Directives []*Directive `json:"-"`
}

// Config is a parsed set of files; Files[0] is the main file.
type Config struct {
	Files  []*File
	byPath map[string]*File
}

const (
	maxDepth      = 64
	maxDirectives = 500000
)

// ParseDump parses `nginx -T` output (or a single plain config file).
func ParseDump(src, defaultFile string) (*Config, error) {
	toks, err := Lex(src, defaultFile)
	if err != nil {
		return nil, err
	}
	// split tokens per file section, and compute per-file checksums from raw text
	rawByFile := splitRaw(src, defaultFile)
	cfg := &Config{byPath: map[string]*File{}}
	var cur []Token
	curFile := defaultFile
	flush := func() error {
		if len(cur) == 0 && curFile == defaultFile {
			return nil
		}
		p := &parser{toks: cur}
		ds, err := p.parseBlock(0, false)
		if err != nil {
			return err
		}
		f := &File{Path: curFile, Directives: ds, Sha256: sum(rawByFile[curFile])}
		if _, dup := cfg.byPath[curFile]; !dup {
			cfg.byPath[curFile] = f
			cfg.Files = append(cfg.Files, f)
		}
		return nil
	}
	for _, t := range toks {
		if t.Kind == TokFileMarker {
			if err := flush(); err != nil {
				return nil, err
			}
			cur, curFile = nil, t.Value
			continue
		}
		cur = append(cur, t)
	}
	if err := flush(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func sum(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// splitRaw maps file path -> raw section text (for checksums).
func splitRaw(src, defaultFile string) map[string]string {
	out := map[string]string{}
	cur := defaultFile
	var sb strings.Builder
	for _, ln := range strings.SplitAfter(src, "\n") {
		t := strings.TrimRight(ln, "\r\n ")
		if strings.HasPrefix(t, markerPrefix) && strings.HasSuffix(t, ":") {
			out[cur] += sb.String()
			sb.Reset()
			cur = strings.TrimSuffix(t[len(markerPrefix):], ":")
			continue
		}
		sb.WriteString(ln)
	}
	out[cur] += sb.String()
	return out
}

type parser struct {
	toks  []Token
	pos   int
	count int
}

func (p *parser) parseBlock(depth int, inBlock bool) ([]*Directive, error) {
	if depth > maxDepth {
		return nil, p.errAt("nesting too deep")
	}
	var out []*Directive
	for p.pos < len(p.toks) {
		t := p.toks[p.pos]
		switch t.Kind {
		case TokCloseBrace:
			if !inBlock {
				return nil, &SyntaxError{t.File, t.Line, `unexpected "}"`}
			}
			p.pos++
			return out, nil
		case TokSemicolon:
			return nil, &SyntaxError{t.File, t.Line, `unexpected ";"`}
		case TokOpenBrace:
			return nil, &SyntaxError{t.File, t.Line, `unexpected "{"`}
		}
		// t is a word: directive name
		p.count++
		if p.count > maxDirectives {
			return nil, p.errAt("too many directives")
		}
		d := &Directive{Name: t.Value, File: t.File, Line: t.Line}
		p.pos++
		for {
			if p.pos >= len(p.toks) {
				return nil, &SyntaxError{t.File, t.Line, `unexpected end of file, expecting ";" or "}"`}
			}
			a := p.toks[p.pos]
			if a.Kind == TokWord {
				d.Args = append(d.Args, a.Value)
				p.pos++
				continue
			}
			if a.Kind == TokSemicolon {
				p.pos++
				break
			}
			if a.Kind == TokOpenBrace {
				p.pos++
				d.IsBlock = true
				child, err := p.parseBlock(depth+1, true)
				if err != nil {
					return nil, err
				}
				d.Block = child
				if d.Block == nil {
					d.Block = []*Directive{}
				}
				break
			}
			return nil, &SyntaxError{a.File, a.Line, `unexpected "}"`}
		}
		out = append(out, d)
	}
	if inBlock {
		f, l := "", 0
		if len(p.toks) > 0 {
			f, l = p.toks[len(p.toks)-1].File, p.toks[len(p.toks)-1].Line
		}
		return nil, &SyntaxError{f, l, `unexpected end of file, expecting "}"`}
	}
	return out, nil
}

func (p *parser) errAt(msg string) error {
	if p.pos < len(p.toks) {
		return &SyntaxError{p.toks[p.pos].File, p.toks[p.pos].Line, msg}
	}
	return &SyntaxError{"", 0, msg}
}

// IncludeIssue records an include that could not be resolved from the dump.
type IncludeIssue struct {
	Pattern string `json:"pattern"`
	File    string `json:"file"`
	Line    int    `json:"line"`
	Reason  string `json:"reason"`
}

// Resolve returns the effective directive tree of the main file with
// `include` directives expanded from the other files in the dump. Directives
// keep their origin File/Line and get IncludedFrom chains. The include
// directive itself is retained (with its expansion following it) so callers
// can still see where config came from.
func (c *Config) Resolve() ([]*Directive, []IncludeIssue) {
	if len(c.Files) == 0 {
		return nil, nil
	}
	main := c.Files[0]
	baseDir := path.Dir(main.Path)
	var issues []IncludeIssue
	paths := make([]string, 0, len(c.Files))
	for _, f := range c.Files {
		paths = append(paths, f.Path)
	}
	sort.Strings(paths)
	var expand func(ds []*Directive, chain []string, depth int, stack map[string]bool) []*Directive
	expand = func(ds []*Directive, chain []string, depth int, stack map[string]bool) []*Directive {
		var out []*Directive
		for _, d := range ds {
			cp := *d
			cp.IncludedFrom = chain
			if d.IsBlock {
				cp.Block = expand(d.Block, chain, depth, stack)
				if cp.Block == nil {
					cp.Block = []*Directive{}
				}
			}
			out = append(out, &cp)
			if d.Name != "include" || len(d.Args) != 1 {
				continue
			}
			pat := d.Args[0]
			if !path.IsAbs(pat) {
				pat = path.Join(baseDir, pat)
			}
			var matched []string
			for _, p := range paths {
				if ok, _ := path.Match(pat, p); ok {
					matched = append(matched, p)
				}
			}
			if len(matched) == 0 {
				reason := "no file in dump matches include"
				if strings.ContainsAny(pat, "*?[") {
					reason = "glob matched no files"
				}
				issues = append(issues, IncludeIssue{Pattern: d.Args[0], File: d.File, Line: d.Line, Reason: reason})
				continue
			}
			for _, m := range matched {
				if stack[m] || depth >= 16 {
					issues = append(issues, IncludeIssue{Pattern: d.Args[0], File: d.File, Line: d.Line, Reason: "recursive include"})
					continue
				}
				stack[m] = true
				sub := append(append([]string{}, chain...), d.File+":"+itoa(d.Line))
				out = append(out, expand(c.byPath[m].Directives, sub, depth+1, stack)...)
				delete(stack, m)
			}
		}
		return out
	}
	return expand(main.Directives, nil, 0, map[string]bool{main.Path: true}), issues
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var b [20]byte
	p := len(b)
	for i > 0 {
		p--
		b[p] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		p--
		b[p] = '-'
	}
	return string(b[p:])
}
