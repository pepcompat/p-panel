// Package nginxops implements the P3 typed nginx jobs (docs/AGENT_PROTOCOL.md
// "Nginx typed jobs (P3) — authoritative"): strict param decoding, the
// agent-side path policy, backups with manifest, atomic writes, `nginx -t`,
// reload, loopback-only postchecks and verified restore.
//
// Every process spawn goes through internal/execx (fixed argv, timeout, output
// cap). There is no way to make this package run an arbitrary command.
package nginxops

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/ppanel/ppanel/apps/agent/internal/jobs"
)

// Contract constants (packages/shared-contracts/src/jobs.ts).
const (
	LogicalRoot = "/etc/nginx"
	ManagedDir  = "/etc/nginx/ppanel-managed"
	// ManagedIncludeFile is the ONE file outside ManagedDir that may be created
	// ("enable managed routing": `include /etc/nginx/ppanel-managed/*/*.conf;`).
	ManagedIncludeFile = "/etc/nginx/conf.d/ppanel-managed.conf"
	MaxFileBytes       = 262144
	MaxFiles           = 20
	MaxPostchecks      = 10
)

// Error codes (NGINX_ERROR_CODES).
const (
	CodePathNotAllowed       = "PATH_NOT_ALLOWED"
	CodeDriftDetected        = "DRIFT_DETECTED"
	CodeNginxTestFailed      = "NGINX_TEST_FAILED"
	CodeReloadFailedReverted = "RELOAD_FAILED_REVERTED"
	CodePostcheckReverted    = "POSTCHECK_FAILED_REVERTED"
	CodeRevertFailedManual   = "REVERT_FAILED_MANUAL_RECOVERY"
	CodeBackupNotFound       = "BACKUP_NOT_FOUND"
	CodeNginxNotPresent      = "NGINX_NOT_PRESENT"
)

var (
	pathRe       = regexp.MustCompile(`^/etc/nginx/[A-Za-z0-9._/-]{1,200}$`)
	shaRe        = regexp.MustCompile(`^[a-f0-9]{64}$`)
	uuidRe       = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	hostHeaderRe = regexp.MustCompile(`^[A-Za-z0-9.-]{1,253}$`)
	probePathRe  = regexp.MustCompile(`^/[A-Za-z0-9._~/?=&%-]{0,200}$`)
)

func pathErr(format string, a ...any) *jobs.Error {
	return jobs.Errorf(CodePathNotAllowed, format, a...)
}

// ValidPath enforces the lexical part of the path policy: contract regex, no
// ".." segment, no "//", and canonical (filepath.Clean) form.
func ValidPath(p string) error {
	if !pathRe.MatchString(p) {
		return pathErr("path %q does not match ^/etc/nginx/[A-Za-z0-9._/-]{1,200}$", p)
	}
	if strings.Contains(p, "//") {
		return pathErr("path %q contains //", p)
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == ".." {
			return pathErr("path %q contains ..", p)
		}
	}
	if filepath.Clean(p) != p {
		return pathErr("path %q is not canonical", p)
	}
	return nil
}

// CreatableLogical is the lexical creation rule: new files only under
// ManagedDir, plus exactly ManagedIncludeFile.
func CreatableLogical(p string) bool {
	return strings.HasPrefix(p, ManagedDir+"/") || p == ManagedIncludeFile
}

// ValidContent enforces size / UTF-8 / NUL rules for new file content.
func ValidContent(path, c string) error {
	if len(c) > MaxFileBytes {
		return pathErr("content for %s is %d bytes (max %d)", path, len(c), MaxFileBytes)
	}
	if !utf8.ValidString(c) {
		return pathErr("content for %s is not valid UTF-8", path)
	}
	if strings.IndexByte(c, 0) >= 0 {
		return pathErr("content for %s contains NUL", path)
	}
	return nil
}

// FileChange is one entry of params.files.
type FileChange struct {
	Path                 string
	ExpectedSha256Before *string // nil = must not exist (create)
	Content              string
}

// Postcheck is one loopback probe.
type Postcheck struct {
	HostHeader   string
	Path         string
	Scheme       string
	Port         int
	ExpectStatus []int
}

// RevisionParams are nginx.validate / nginx.apply params.
type RevisionParams struct {
	RevisionID string
	Files      []FileChange
	Postchecks []Postcheck // apply only
}

// ExpectedFile is one entry of nginx.revert params.expectedCurrent.
type ExpectedFile struct {
	Path   string
	Sha256 *string // nil = must not exist
}

// RevertParams are nginx.revert params.
type RevertParams struct {
	RevisionID      string
	ExpectedCurrent []ExpectedFile
}

// ReadParams are nginx.read_files params.
type ReadParams struct {
	Paths []string
}

type fileChangeWire struct {
	Path                 *string         `json:"path"`
	ExpectedSha256Before json.RawMessage `json:"expectedSha256Before"`
	Content              *string         `json:"content"`
}

type postcheckWire struct {
	HostHeader   *string `json:"hostHeader"`
	Path         *string `json:"path"`
	Scheme       *string `json:"scheme"`
	Port         *int    `json:"port"`
	ExpectStatus []int   `json:"expectStatus"`
}

// nullableSha decodes a required-but-nullable sha256 field.
func nullableSha(field string, raw json.RawMessage) (*string, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("%s is required (sha256 hex or null)", field)
	}
	if string(raw) == "null" {
		return nil, nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, fmt.Errorf("%s must be a string or null", field)
	}
	if !shaRe.MatchString(s) {
		return nil, fmt.Errorf("%s must be 64 lowercase hex chars", field)
	}
	return &s, nil
}

func decodeFiles(ws []fileChangeWire) ([]FileChange, error) {
	if len(ws) < 1 || len(ws) > MaxFiles {
		return nil, fmt.Errorf("files must contain 1..%d entries", MaxFiles)
	}
	seen := map[string]bool{}
	out := make([]FileChange, 0, len(ws))
	for i, w := range ws {
		if w.Path == nil || w.Content == nil {
			return nil, fmt.Errorf("files[%d]: path and content are required", i)
		}
		if err := ValidPath(*w.Path); err != nil {
			return nil, err
		}
		if seen[*w.Path] {
			return nil, fmt.Errorf("files[%d]: duplicate path %s", i, *w.Path)
		}
		seen[*w.Path] = true
		sha, err := nullableSha(fmt.Sprintf("files[%d].expectedSha256Before", i), w.ExpectedSha256Before)
		if err != nil {
			return nil, err
		}
		if err := ValidContent(*w.Path, *w.Content); err != nil {
			return nil, err
		}
		if sha == nil && !CreatableLogical(*w.Path) {
			return nil, pathErr("creating %s is not allowed: new files only under %s/ (or %s)", *w.Path, ManagedDir, ManagedIncludeFile)
		}
		out = append(out, FileChange{Path: *w.Path, ExpectedSha256Before: sha, Content: *w.Content})
	}
	return out, nil
}

func decodeRevisionID(id *string) (string, error) {
	if id == nil || !uuidRe.MatchString(*id) {
		return "", fmt.Errorf("revisionId must be a UUID")
	}
	return strings.ToLower(*id), nil
}

// DecodeRead strictly decodes nginx.read_files params.
func DecodeRead(raw json.RawMessage) (ReadParams, error) {
	var w struct {
		Paths []string `json:"paths"`
	}
	if err := jobs.DecodeStrict(raw, &w); err != nil {
		return ReadParams{}, err
	}
	if len(w.Paths) < 1 || len(w.Paths) > MaxFiles {
		return ReadParams{}, fmt.Errorf("paths must contain 1..%d entries", MaxFiles)
	}
	for _, p := range w.Paths {
		if err := ValidPath(p); err != nil {
			return ReadParams{}, err
		}
	}
	return ReadParams{Paths: w.Paths}, nil
}

// DecodeValidate strictly decodes nginx.validate params (no postchecks key).
func DecodeValidate(raw json.RawMessage) (RevisionParams, error) {
	var w struct {
		RevisionID *string          `json:"revisionId"`
		Files      []fileChangeWire `json:"files"`
	}
	if err := jobs.DecodeStrict(raw, &w); err != nil {
		return RevisionParams{}, err
	}
	id, err := decodeRevisionID(w.RevisionID)
	if err != nil {
		return RevisionParams{}, err
	}
	files, err := decodeFiles(w.Files)
	if err != nil {
		return RevisionParams{}, err
	}
	return RevisionParams{RevisionID: id, Files: files}, nil
}

// DecodeApply strictly decodes nginx.apply params (postchecks default []).
func DecodeApply(raw json.RawMessage) (RevisionParams, error) {
	var w struct {
		RevisionID *string          `json:"revisionId"`
		Files      []fileChangeWire `json:"files"`
		Postchecks []postcheckWire  `json:"postchecks"`
	}
	if err := jobs.DecodeStrict(raw, &w); err != nil {
		return RevisionParams{}, err
	}
	id, err := decodeRevisionID(w.RevisionID)
	if err != nil {
		return RevisionParams{}, err
	}
	files, err := decodeFiles(w.Files)
	if err != nil {
		return RevisionParams{}, err
	}
	if len(w.Postchecks) > MaxPostchecks {
		return RevisionParams{}, fmt.Errorf("postchecks: max %d entries", MaxPostchecks)
	}
	pcs := make([]Postcheck, 0, len(w.Postchecks))
	for i, pw := range w.Postchecks {
		pc := Postcheck{Path: "/", Scheme: "http", ExpectStatus: []int{200}}
		if pw.HostHeader == nil || !hostHeaderRe.MatchString(*pw.HostHeader) {
			return RevisionParams{}, fmt.Errorf("postchecks[%d].hostHeader invalid", i)
		}
		pc.HostHeader = *pw.HostHeader
		if pw.Path != nil {
			if !probePathRe.MatchString(*pw.Path) {
				return RevisionParams{}, fmt.Errorf("postchecks[%d].path invalid", i)
			}
			pc.Path = *pw.Path
		}
		if pw.Scheme != nil {
			if *pw.Scheme != "http" && *pw.Scheme != "https" {
				return RevisionParams{}, fmt.Errorf("postchecks[%d].scheme must be http|https", i)
			}
			pc.Scheme = *pw.Scheme
		}
		if pw.Port != nil {
			if *pw.Port < 1 || *pw.Port > 65535 {
				return RevisionParams{}, fmt.Errorf("postchecks[%d].port must be 1..65535", i)
			}
			pc.Port = *pw.Port
		} else if pc.Scheme == "https" {
			pc.Port = 443
		} else {
			pc.Port = 80
		}
		if pw.ExpectStatus != nil {
			if len(pw.ExpectStatus) < 1 || len(pw.ExpectStatus) > 10 {
				return RevisionParams{}, fmt.Errorf("postchecks[%d].expectStatus must have 1..10 entries", i)
			}
			for _, s := range pw.ExpectStatus {
				if s < 100 || s > 599 {
					return RevisionParams{}, fmt.Errorf("postchecks[%d].expectStatus values must be 100..599", i)
				}
			}
			pc.ExpectStatus = pw.ExpectStatus
		}
		pcs = append(pcs, pc)
	}
	return RevisionParams{RevisionID: id, Files: files, Postchecks: pcs}, nil
}

// DecodeRevert strictly decodes nginx.revert params.
func DecodeRevert(raw json.RawMessage) (RevertParams, error) {
	var w struct {
		RevisionID      *string `json:"revisionId"`
		ExpectedCurrent []struct {
			Path   *string         `json:"path"`
			Sha256 json.RawMessage `json:"sha256"`
		} `json:"expectedCurrent"`
	}
	if err := jobs.DecodeStrict(raw, &w); err != nil {
		return RevertParams{}, err
	}
	id, err := decodeRevisionID(w.RevisionID)
	if err != nil {
		return RevertParams{}, err
	}
	if len(w.ExpectedCurrent) < 1 || len(w.ExpectedCurrent) > MaxFiles {
		return RevertParams{}, fmt.Errorf("expectedCurrent must contain 1..%d entries", MaxFiles)
	}
	seen := map[string]bool{}
	out := RevertParams{RevisionID: id}
	for i, e := range w.ExpectedCurrent {
		if e.Path == nil {
			return RevertParams{}, fmt.Errorf("expectedCurrent[%d].path is required", i)
		}
		if err := ValidPath(*e.Path); err != nil {
			return RevertParams{}, err
		}
		if seen[*e.Path] {
			return RevertParams{}, fmt.Errorf("expectedCurrent[%d]: duplicate path %s", i, *e.Path)
		}
		seen[*e.Path] = true
		sha, err := nullableSha(fmt.Sprintf("expectedCurrent[%d].sha256", i), e.Sha256)
		if err != nil {
			return RevertParams{}, err
		}
		out.ExpectedCurrent = append(out.ExpectedCurrent, ExpectedFile{Path: *e.Path, Sha256: sha})
	}
	return out, nil
}
