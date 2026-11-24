package sshkeys

import (
	"bufio"
	"bytes"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/ppanel/ppanel/apps/agent/internal/safefs"
)

// DefaultEtcDir is where sshd keeps its host keys and configuration.
const DefaultEtcDir = "/etc/ssh"

// HostKey is one host public key fingerprint (facts).
type HostKey struct {
	Algorithm         string `json:"algorithm"`
	FingerprintSha256 string `json:"fingerprintSha256"`
}

// Facts is the `ssh` agent fact (contract §2). Port is 22 when sshd_config
// exists without a Port line, and OMITTED when sshd_config is absent or
// unreadable (the Center's schema defaults a missing port to 22 and would
// discard the whole fact on an explicit null).
type Facts struct {
	HostKeys []HostKey `json:"hostKeys"`
	Port     *int      `json:"port,omitempty"`
}

// Limits for the facts collector.
const (
	maxHostKeyFiles   = 16
	maxHostKeyFile    = 16 << 10
	maxConfigFile     = 256 << 10
	maxConfigIncludes = 32
	maxIncludeDepth   = 4
)

// CollectFacts reads <etcDir>/ssh_host_*_key.pub and <etcDir>/sshd_config.
// It returns nil (→ `ssh: null`) when no valid host public key is present.
// Only PUBLIC key files are read; the private host keys are never opened.
func CollectFacts(etcDir string) *Facts {
	if etcDir == "" {
		etcDir = DefaultEtcDir
	}
	// resolve the (root-owned) directory once; files inside are never followed
	if d, err := filepath.EvalSymlinks(etcDir); err == nil {
		etcDir = d
	}
	files, _ := filepath.Glob(filepath.Join(etcDir, "ssh_host_*_key.pub"))
	sort.Strings(files)
	if len(files) > maxHostKeyFiles {
		files = files[:maxHostKeyFiles]
	}
	seen := map[string]bool{}
	var keys []HostKey
	for _, f := range files {
		if !strings.HasSuffix(f, "_key.pub") {
			continue
		}
		b, _, err := safefs.ReadFileNoFollow(f, maxHostKeyFile)
		if err != nil {
			continue
		}
		line := strings.TrimRight(string(firstLine(b)), "\r")
		k, err := parsePublicKey(line, hostKeyTypes, 1024)
		if err != nil {
			continue
		}
		fp := k.Fingerprint()
		if seen[fp] {
			continue
		}
		seen[fp] = true
		keys = append(keys, HostKey{Algorithm: k.Type, FingerprintSha256: fp})
	}
	if len(keys) == 0 {
		return nil
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].Algorithm != keys[j].Algorithm {
			return keys[i].Algorithm < keys[j].Algorithm
		}
		return keys[i].FingerprintSha256 < keys[j].FingerprintSha256
	})
	return &Facts{HostKeys: keys, Port: sshdPort(etcDir)}
}

func firstLine(b []byte) []byte {
	if i := bytes.IndexByte(b, '\n'); i >= 0 {
		return b[:i]
	}
	return b
}

// sshdPort returns the first `Port` of sshd_config (Include directives are
// followed in order, like sshd), 22 when none is set, nil when sshd_config
// cannot be read.
func sshdPort(etcDir string) *int {
	main := filepath.Join(etcDir, "sshd_config")
	if _, _, err := safefs.ReadFileNoFollow(main, maxConfigFile); err != nil {
		return nil
	}
	budget := maxConfigIncludes
	if p, found := scanPort(etcDir, main, 0, &budget); found {
		return &p
	}
	p := 22
	return &p
}

// scanPort scans one config file. Port is not allowed inside Match blocks, so
// scanning stops at the first Match line of a file.
func scanPort(etcDir, file string, depth int, budget *int) (int, bool) {
	if depth > maxIncludeDepth || *budget <= 0 {
		return 0, false
	}
	*budget--
	b, _, err := safefs.ReadFileNoFollow(file, maxConfigFile)
	if err != nil {
		return 0, false
	}
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 0, 4096), maxConfigFile)
	for sc.Scan() {
		kw, args := splitDirective(sc.Text())
		switch kw {
		case "match":
			return 0, false
		case "port":
			if len(args) > 0 {
				if n, err := strconv.Atoi(args[0]); err == nil && n >= 1 && n <= 65535 {
					return n, true
				}
			}
		case "include":
			for _, pat := range args {
				if !filepath.IsAbs(pat) {
					pat = filepath.Join(etcDir, pat)
				}
				matches, _ := filepath.Glob(pat)
				sort.Strings(matches)
				for _, m := range matches {
					if n, ok := scanPort(etcDir, filepath.Clean(m), depth+1, budget); ok {
						return n, true
					}
				}
			}
		}
	}
	return 0, false
}

// splitDirective returns the lower-cased keyword and its arguments
// ("Keyword value", "Keyword=value", comments and blank lines ignored).
func splitDirective(line string) (string, []string) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return "", nil
	}
	kw := line
	rest := ""
	if i := strings.IndexAny(line, " \t="); i >= 0 {
		kw, rest = line[:i], strings.TrimLeft(line[i:], " \t")
		rest = strings.TrimLeft(strings.TrimPrefix(rest, "="), " \t")
	}
	var args []string
	for _, f := range strings.Fields(rest) {
		if strings.HasPrefix(f, "#") {
			break
		}
		args = append(args, strings.Trim(f, `"`))
	}
	return strings.ToLower(kw), args
}
