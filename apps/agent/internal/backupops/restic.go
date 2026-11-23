package backupops

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/ppanel/ppanel/apps/agent/internal/execx"
	"github.com/ppanel/ppanel/apps/agent/internal/jobs"
	"github.com/ppanel/ppanel/apps/agent/internal/transport"
)

// MinResticMajor/MinResticMinor is the minimum supported restic (0.17: exit
// codes 10–12, --stdin-from-command, restore --dry-run/--delete, dump --target,
// RESTIC_REST_USERNAME/PASSWORD).
const (
	MinResticMajor = 0
	MinResticMinor = 17
)

var resticVersionRe = regexp.MustCompile(`restic (\d+)\.(\d+)\.(\d+)`)

// ParseResticVersion extracts "X.Y.Z" from `restic version` output and
// reports whether it is >= 0.17.
func ParseResticVersion(out string) (string, bool) {
	m := resticVersionRe.FindStringSubmatch(out)
	if m == nil {
		return "", false
	}
	maj, _ := strconv.Atoi(m[1])
	minor, _ := strconv.Atoi(m[2])
	v := m[1] + "." + m[2] + "." + m[3]
	return v, maj > MinResticMajor || (maj == MinResticMajor && minor >= MinResticMinor)
}

// DetectRestic runs `<bin> version` (fixed argv) and returns the version.
func DetectRestic(ctx context.Context, run execx.CmdRunner, bin string) (string, error) {
	res, err := run.RunCmd(ctx, execx.Cmd{Binary: bin, Args: []string{"version"}, Timeout: 10 * time.Second, MaxOut: 4 << 10})
	if err != nil {
		return "", err
	}
	if res.ExitCode != 0 {
		return "", fmt.Errorf("restic version exited %d", res.ExitCode)
	}
	v, ok := ParseResticVersion(string(res.Stdout))
	if v == "" {
		return "", fmt.Errorf("unrecognised restic version output")
	}
	if !ok {
		return v, fmt.Errorf("restic %s is too old (need >= %d.%d)", v, MinResticMajor, MinResticMinor)
	}
	return v, nil
}

// Creds are the job's restic credentials (memory only).
type Creds struct {
	RepoPassword string
	RestUser     string
	RestPassword string
}

func credsFrom(s *transport.JobSecrets) (Creds, error) {
	if s == nil || s.Restic == nil || s.Restic.RepoPassword == "" {
		return Creds{}, fmt.Errorf("restic repository credentials not delivered")
	}
	return Creds{RepoPassword: s.Restic.RepoPassword, RestUser: s.Restic.RestUser, RestPassword: s.Restic.RestPassword}, nil
}

// Values lists the secret values (for redaction).
func (c Creds) Values() []string { return []string{c.RepoPassword, c.RestPassword} }

// Env is the restic credential environment (KEY=VALUE). Secrets are passed to
// restic ONLY this way, never as argv.
func (c Creds) Env() []string {
	env := []string{"RESTIC_PASSWORD=" + c.RepoPassword}
	if c.RestUser != "" {
		env = append(env, "RESTIC_REST_USERNAME="+c.RestUser, "RESTIC_REST_PASSWORD="+c.RestPassword)
	}
	return env
}

// BackupArgs builds the restic argv (after the binary / helper entrypoint)
// for one backup target. Never contains a secret.
//
//	[--no-cache] -r <url> backup --json --quiet [--host H] --tag ppanel --tag run=<runId>
//	  --tag policy=<policyId> --tag target=<i> [--tag t…] [--exclude e…] [--limit-upload N]
//	  [--stdin-filename f --stdin-from-command] -- <paths… | command…>
func BackupArgs(p BackupParams, idx int, noCache bool, host string, excludes []string, stdinFile string, rest []string) []string {
	var a []string
	if noCache {
		a = append(a, "--no-cache")
	}
	a = append(a, "-r", p.Repo.ResticURL(), "backup", "--json", "--quiet")
	if host != "" {
		a = append(a, "--host", host)
	}
	a = append(a, "--tag", "ppanel", "--tag", "run="+p.RunID, "--tag", "policy="+p.PolicyID, "--tag", "target="+strconv.Itoa(idx))
	for _, t := range p.Tags {
		a = append(a, "--tag", t)
	}
	for _, e := range excludes {
		a = append(a, "--exclude", e)
	}
	if p.Limits.UploadKiBps > 0 {
		a = append(a, "--limit-upload", strconv.Itoa(p.Limits.UploadKiBps))
	}
	if stdinFile != "" {
		a = append(a, "--stdin-filename", stdinFile, "--stdin-from-command")
	}
	a = append(a, "--")
	return append(a, rest...)
}

// BackupSummary is restic's backup --json summary message.
type BackupSummary struct {
	MessageType         string  `json:"message_type"`
	FilesNew            int64   `json:"files_new"`
	FilesChanged        int64   `json:"files_changed"`
	FilesUnmodified     int64   `json:"files_unmodified"`
	DataAdded           int64   `json:"data_added"`
	TotalFilesProcessed int64   `json:"total_files_processed"`
	TotalBytesProcessed int64   `json:"total_bytes_processed"`
	TotalDuration       float64 `json:"total_duration"`
	SnapshotID          string  `json:"snapshot_id"`
}

// ResticMessage is any restic --json line we care about.
type ResticMessage struct {
	MessageType string `json:"message_type"`
	// exit_error
	Code    int    `json:"code"`
	Message string `json:"message"`
	// error
	Error *struct {
		Message string `json:"message"`
	} `json:"error"`
	During string `json:"during"`
	Item   string `json:"item"`
	// verbose_status (restore)
	Action string `json:"action"`
	Size   int64  `json:"size"`
	// restore summary
	TotalFiles    int64 `json:"total_files"`
	FilesRestored int64 `json:"files_restored"`
	FilesSkipped  int64 `json:"files_skipped"`
	FilesDeleted  int64 `json:"files_deleted"`
	TotalBytes    int64 `json:"total_bytes"`
	BytesRestored int64 `json:"bytes_restored"`
	// check summary
	NumErrors int `json:"num_errors"`
}

// ParsedOutput is the scan of a restic --json stdout.
type ParsedOutput struct {
	Summary   *BackupSummary
	Restore   *ResticMessage // restore/check summary
	ExitError *ResticMessage
	Errors    []string // per-item error messages (bounded)
	Items     []ResticMessage
	ItemCount int
}

// ParseJSONLines scans restic --json output (one JSON object per line). Lines
// that are not JSON are ignored. keepItems bounds verbose_status entries kept.
func ParseJSONLines(out []byte, keepItems int) ParsedOutput {
	var p ParsedOutput
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 || line[0] != '{' {
			continue
		}
		var m ResticMessage
		if json.Unmarshal(line, &m) != nil {
			continue
		}
		switch m.MessageType {
		case "summary":
			var s BackupSummary
			if json.Unmarshal(line, &s) == nil && s.SnapshotID != "" {
				p.Summary = &s
			} else {
				mm := m
				p.Restore = &mm
			}
		case "exit_error":
			mm := m
			p.ExitError = &mm
		case "error":
			if m.Error != nil && len(p.Errors) < 20 {
				p.Errors = append(p.Errors, truncate(m.Error.Message, 500))
			}
		case "verbose_status":
			p.ItemCount++
			if len(p.Items) < keepItems {
				p.Items = append(p.Items, m)
			}
		}
	}
	return p
}

// ParseSummary returns the backup summary from restic backup --json output.
func ParseSummary(out []byte) (*BackupSummary, error) {
	p := ParseJSONLines(out, 0)
	if p.Summary == nil {
		if p.ExitError != nil {
			return nil, fmt.Errorf("%s", p.ExitError.Message)
		}
		return nil, fmt.Errorf("no backup summary in restic output")
	}
	return p.Summary, nil
}

var (
	unreachableRe = regexp.MustCompile(`(?i)connection refused|no such host|i/o timeout|dial tcp|network is unreachable|tls: |x509: |unexpected HTTP response \((401|403)\)|repository does not exist|unable to open config file|wrong password|server response unexpected|Client.Timeout`)
	lockedRe      = regexp.MustCompile(`(?i)repository is already locked|unable to create lock|failed to lock`)
	notFoundRe    = regexp.MustCompile(`(?i)no matching ID found|failed to find snapshot|no snapshot found|snapshot .* not found|invalid id`)
)

// ClassifyFailure maps a restic failure to a P6 error code: exit 10/12 or
// connectivity → REPO_UNREACHABLE; exit 11 / lock text → REPO_LOCKED; unknown
// snapshot → SNAPSHOT_NOT_FOUND; otherwise def.
func ClassifyFailure(exitCode int, text, def string) string {
	switch {
	case exitCode == 11 || lockedRe.MatchString(text):
		return CodeRepoLocked
	case exitCode == 10 || exitCode == 12 || unreachableRe.MatchString(text):
		return CodeRepoUnreachable
	case notFoundRe.MatchString(text):
		return CodeSnapshotNotFound
	}
	return def
}

// failureText summarises a failed restic run (exit_error message, item
// errors, else the stderr tail).
func failureText(stdout, stderr []byte) string {
	p := ParseJSONLines(stdout, 0)
	var parts []string
	if p.ExitError != nil {
		parts = append(parts, p.ExitError.Message)
	}
	parts = append(parts, p.Errors...)
	if len(parts) == 0 {
		s := strings.TrimSpace(string(stderr))
		if len(s) > 1500 {
			s = s[len(s)-1500:]
		}
		parts = append(parts, s)
	}
	return truncate(strings.Join(parts, "; "), 2000)
}

func resticErr(code string, format string, a ...any) *jobs.Error {
	return jobs.Errorf(code, format, a...)
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

// SnapshotJSON is one entry of restic snapshots --json.
type SnapshotJSON struct {
	ID       string   `json:"id"`
	ShortID  string   `json:"short_id"`
	Time     string   `json:"time"`
	Tags     []string `json:"tags"`
	Paths    []string `json:"paths"`
	Hostname string   `json:"hostname"`
	Summary  *struct {
		TotalBytesProcessed int64 `json:"total_bytes_processed"`
		TotalFilesProcessed int64 `json:"total_files_processed"`
	} `json:"summary"`
}

// Snapshot is a backup.snapshots output entry.
type Snapshot struct {
	ID        string   `json:"id"`
	ShortID   string   `json:"shortId"`
	Time      string   `json:"time"`
	Tags      []string `json:"tags"`
	Paths     []string `json:"paths"`
	Hostname  string   `json:"hostname"`
	SizeBytes *int64   `json:"sizeBytes,omitempty"`
}

// ParseSnapshots converts restic snapshots --json output.
func ParseSnapshots(out []byte) ([]Snapshot, error) {
	var raw []SnapshotJSON
	if err := json.Unmarshal(bytes.TrimSpace(out), &raw); err != nil {
		return nil, fmt.Errorf("parse restic snapshots: %w", err)
	}
	res := make([]Snapshot, 0, len(raw))
	for _, s := range raw {
		if s.Tags == nil {
			s.Tags = []string{}
		}
		if s.Paths == nil {
			s.Paths = []string{}
		}
		sn := Snapshot{ID: s.ID, ShortID: s.ShortID, Time: s.Time, Tags: s.Tags, Paths: s.Paths, Hostname: s.Hostname}
		if s.Summary != nil {
			v := s.Summary.TotalBytesProcessed
			sn.SizeBytes = &v
		}
		res = append(res, sn)
	}
	return res, nil
}
