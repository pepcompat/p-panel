// Package backupops implements the P6 backup.* / restore.run jobs
// (docs/AGENT_PROTOCOL.md "Backups and restores (P6) — authoritative").
//
//   - paths targets: the HOST restic binary via internal/execx (fixed argv);
//   - volume / postgres / mysql targets: a hardened helper container
//     (backup.helperImage) running restic (+ pg_dump / mysqldump via
//     --stdin-from-command) as its fixed container command — no shell, no exec;
//   - repository credentials and DB passwords are passed ONLY via env, never
//     argv, and are redacted from every output and error.
//
// The agent's restic credential is append-only (rest-server --private-repos
// --append-only): it can create and read snapshots, never forget/prune.
package backupops

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/ppanel/ppanel/apps/agent/internal/containerops"
	"github.com/ppanel/ppanel/apps/agent/internal/jobs"
)

// Error codes (packages/shared-contracts BACKUP_ERROR_CODES).
const (
	CodeResticUnavailable     = "RESTIC_UNAVAILABLE"
	CodeRepoUnreachable       = "REPO_UNREACHABLE"
	CodeRepoLocked            = "REPO_LOCKED"
	CodeBackupFailed          = "BACKUP_FAILED"
	CodeBackupPartial         = "BACKUP_PARTIAL"
	CodeDumpFailed            = "DUMP_FAILED"
	CodeSnapshotNotFound      = "SNAPSHOT_NOT_FOUND"
	CodeVerifyFailed          = "VERIFY_FAILED"
	CodeRestoreFailed         = "RESTORE_FAILED"
	CodeRestoreTargetExists   = "RESTORE_TARGET_EXISTS"
	CodeHelperImageNotAllowed = "HELPER_IMAGE_NOT_ALLOWED"
)

// Shared-contracts mirrors (jobs.ts P6 section) plus agent-side tightening.
var (
	hostPathRe   = regexp.MustCompile(`^/[A-Za-z0-9._@+/-]{0,400}$`)
	snapshotRe   = regexp.MustCompile(`^[a-f0-9]{8}([a-f0-9]{56})?$`)
	tagRe        = regexp.MustCompile(`^[a-z0-9][a-z0-9_.=:-]{0,80}$`)
	excludeRe    = regexp.MustCompile(`^[A-Za-z0-9._*?/\[\]-]{1,200}$`)
	repoURLRe    = regexp.MustCompile(`^(rest:)?https?://[A-Za-z0-9.-]{1,253}(:[0-9]{1,5})?/[A-Za-z0-9._/-]{0,200}$`)
	volumeRe     = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,40}$`)
	serviceRe    = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,30}$`)
	dbIdentRe    = regexp.MustCompile(`^[A-Za-z0-9_-]{1,63}$`)
	sha256HexRe  = regexp.MustCompile(`^[a-f0-9]{64}$`)
	tableNameRe  = regexp.MustCompile(`^[A-Za-z0-9_$.]{1,130}$`)
	deniedRoots  = []string{"/proc", "/sys", "/dev"}
	targetTypes  = map[string]bool{"paths": true, "volume": true, "postgres": true, "mysql": true}
	restoreModes = map[string]map[string]bool{
		"paths":    {"staging": true, "in_place": true},
		"volume":   {"staging": true, "in_place": true},
		"postgres": {"scratch": true, "in_place": true},
		"mysql":    {"scratch": true, "in_place": true},
	}
)

// MaxManifestFiles bounds the per-run file manifest (beyond → truncated).
const MaxManifestFiles = 10000

// MaxTables bounds the per-DB exact row counts.
const MaxTables = 200

// MaxConstraints bounds the per-DB constraint name list.
const MaxConstraints = 1000

func invalid(format string, a ...any) error {
	return jobs.Errorf(jobs.RejectedInvalidParams, format, a...)
}

// RepoRef is backupRepoRefSchema.
type RepoRef struct {
	URL          string `json:"url"`
	RepositoryID string `json:"repositoryId"`
}

func (r RepoRef) validate() error {
	if len(r.URL) > 500 || !repoURLRe.MatchString(r.URL) || strings.Contains(r.URL, "..") {
		return invalid("repo.url must be a rest-server URL without credentials")
	}
	if !containerops.UUIDRe.MatchString(r.RepositoryID) {
		return invalid("repo.repositoryId must be a uuid")
	}
	return nil
}

// ResticURL is the restic repository string (rest: prefix added).
func (r RepoRef) ResticURL() string {
	if strings.HasPrefix(r.URL, "rest:") {
		return r.URL
	}
	return "rest:" + r.URL
}

// Target is one backup target (backupTargetSchema, discriminated by type).
type Target struct {
	Type string `json:"type"`
	// paths
	Paths    []string `json:"paths,omitempty"`
	Excludes []string `json:"excludes,omitempty"`
	// volume / db
	App    string `json:"app,omitempty"`
	Volume string `json:"volume,omitempty"`
	// db
	Service           string `json:"service,omitempty"`
	Database          string `json:"database,omitempty"`
	User              string `json:"user,omitempty"`
	PasswordSecretKey string `json:"passwordSecretKey,omitempty"`
	Port              int    `json:"port,omitempty"`
}

// IsDB reports whether the target is a postgres/mysql dump.
func (t Target) IsDB() bool { return t.Type == "postgres" || t.Type == "mysql" }

// NeedsHelper reports whether the target runs in the helper container.
func (t Target) NeedsHelper() bool { return t.Type != "paths" }

// VolumeName is the managed Docker volume of a volume target.
func (t Target) VolumeName() string { return containerops.VolumeName(t.App, t.Volume) }

// DumpFile is the file name a DB dump is stored as in the snapshot.
func (t Target) DumpFile() string { return t.Database + ".sql" }

// DefaultPort is the DB port when the target sets none.
func (t Target) DefaultPort() int {
	if t.Port > 0 {
		return t.Port
	}
	if t.Type == "mysql" {
		return 3306
	}
	return 5432
}

// CheckHostPath validates an absolute host path (canonical, not a pseudo-fs).
func CheckHostPath(p string) error {
	if !hostPathRe.MatchString(p) {
		return fmt.Errorf("path %q is not an allowed absolute path", p)
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == ".." || seg == "." {
			return fmt.Errorf("path %q must be canonical", p)
		}
	}
	if strings.Contains(p, "//") || (len(p) > 1 && strings.HasSuffix(p, "/")) {
		return fmt.Errorf("path %q must be canonical", p)
	}
	for _, d := range deniedRoots {
		if p == d || strings.HasPrefix(p, d+"/") {
			return fmt.Errorf("path %q is under %s", p, d)
		}
	}
	return nil
}

func checkApp(app string) error {
	if !containerops.AppSlugRe.MatchString(app) {
		return invalid("app must be an app slug")
	}
	return nil
}

func checkDBFields(service, database, user, secretKey string, port int) error {
	if !serviceRe.MatchString(service) {
		return invalid("service must match %s", serviceRe)
	}
	// agent-side tightening: never let a value start with '-' (option injection
	// into pg_dump / mysqldump / psql / mysql argv).
	if !dbIdentRe.MatchString(database) || strings.HasPrefix(database, "-") {
		return invalid("database must match %s and not start with '-'", dbIdentRe)
	}
	if !dbIdentRe.MatchString(user) || strings.HasPrefix(user, "-") {
		return invalid("user must match %s and not start with '-'", dbIdentRe)
	}
	if !containerops.EnvKeyRe.MatchString(secretKey) {
		return invalid("passwordSecretKey must be an env key")
	}
	if port < 0 || port > 65535 {
		return invalid("port must be 1..65535")
	}
	return nil
}

func peekType(raw json.RawMessage) (string, error) {
	var t struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(raw, &t); err != nil {
		return "", invalid("target must be an object: %v", err)
	}
	if !targetTypes[t.Type] {
		return "", invalid("unknown target type %q", t.Type)
	}
	return t.Type, nil
}

func decodeTarget(raw json.RawMessage) (Target, error) {
	typ, err := peekType(raw)
	if err != nil {
		return Target{}, err
	}
	switch typ {
	case "paths":
		var p struct {
			Type     string    `json:"type"`
			Paths    []string  `json:"paths"`
			Excludes *[]string `json:"excludes"`
		}
		if err := containerops.DecodeParams(raw, &p); err != nil {
			return Target{}, err
		}
		if len(p.Paths) < 1 || len(p.Paths) > 50 {
			return Target{}, invalid("paths must have 1..50 entries")
		}
		for _, x := range p.Paths {
			if err := CheckHostPath(x); err != nil {
				return Target{}, invalid("%v", err)
			}
		}
		t := Target{Type: typ, Paths: p.Paths, Excludes: []string{}}
		if p.Excludes != nil {
			if len(*p.Excludes) > 100 {
				return Target{}, invalid("excludes must have at most 100 entries")
			}
			for _, e := range *p.Excludes {
				if !excludeRe.MatchString(e) || strings.HasPrefix(e, "-") {
					return Target{}, invalid("exclude %q not allowed", e)
				}
			}
			t.Excludes = *p.Excludes
		}
		return t, nil
	case "volume":
		var p struct {
			Type   string `json:"type"`
			App    string `json:"app"`
			Volume string `json:"volume"`
		}
		if err := containerops.DecodeParams(raw, &p); err != nil {
			return Target{}, err
		}
		if err := checkApp(p.App); err != nil {
			return Target{}, err
		}
		if !volumeRe.MatchString(p.Volume) {
			return Target{}, invalid("volume must match %s", volumeRe)
		}
		return Target{Type: typ, App: p.App, Volume: p.Volume}, nil
	default:
		var p struct {
			Type              string `json:"type"`
			App               string `json:"app"`
			Service           string `json:"service"`
			Database          string `json:"database"`
			User              string `json:"user"`
			PasswordSecretKey string `json:"passwordSecretKey"`
			Port              *int   `json:"port"`
		}
		if err := containerops.DecodeParams(raw, &p); err != nil {
			return Target{}, err
		}
		if err := checkApp(p.App); err != nil {
			return Target{}, err
		}
		port := 0
		if p.Port != nil {
			port = *p.Port
			if port < 1 {
				return Target{}, invalid("port must be 1..65535")
			}
		}
		if err := checkDBFields(p.Service, p.Database, p.User, p.PasswordSecretKey, port); err != nil {
			return Target{}, err
		}
		return Target{Type: typ, App: p.App, Service: p.Service, Database: p.Database, User: p.User,
			PasswordSecretKey: p.PasswordSecretKey, Port: port}, nil
	}
}

// Limits is backupRunParams.limits.
type Limits struct {
	TimeoutSec  int `json:"timeoutSec"`
	UploadKiBps int `json:"uploadKiBps"`
}

// BackupParams is backup.run.
type BackupParams struct {
	RunID       string   `json:"runId"`
	PolicyID    string   `json:"policyId"`
	Repo        RepoRef  `json:"repo"`
	Targets     []Target `json:"targets"`
	Tags        []string `json:"tags"`
	HelperImage string   `json:"helperImage,omitempty"`
	Limits      Limits   `json:"limits"`
}

// NeedsHelper reports whether any target needs the helper container.
func (p BackupParams) NeedsHelper() bool {
	for _, t := range p.Targets {
		if t.NeedsHelper() {
			return true
		}
	}
	return false
}

func checkHelperImage(img string) error {
	if img != "" && (len(img) > 400 || !containerops.ImageDigestRefRe.MatchString(img)) {
		return invalid("helperImage must be pinned by digest")
	}
	return nil
}

// DecodeBackup strictly decodes backup.run params.
func DecodeBackup(raw json.RawMessage) (BackupParams, error) {
	var p struct {
		RunID       string            `json:"runId"`
		PolicyID    string            `json:"policyId"`
		Repo        json.RawMessage   `json:"repo"`
		Targets     []json.RawMessage `json:"targets"`
		Tags        *[]string         `json:"tags"`
		HelperImage *string           `json:"helperImage"`
		Limits      *struct {
			TimeoutSec  *int `json:"timeoutSec"`
			UploadKiBps *int `json:"uploadKiBps"`
		} `json:"limits"`
	}
	if err := containerops.DecodeParams(raw, &p); err != nil {
		return BackupParams{}, err
	}
	out := BackupParams{RunID: p.RunID, PolicyID: p.PolicyID, Tags: []string{}, Limits: Limits{TimeoutSec: 3600}}
	if !containerops.UUIDRe.MatchString(p.RunID) || !containerops.UUIDRe.MatchString(p.PolicyID) {
		return BackupParams{}, invalid("runId and policyId must be uuids")
	}
	repo, err := decodeRepo(p.Repo)
	if err != nil {
		return BackupParams{}, err
	}
	out.Repo = repo
	if len(p.Targets) < 1 || len(p.Targets) > 20 {
		return BackupParams{}, invalid("targets must have 1..20 entries")
	}
	for i, rt := range p.Targets {
		t, err := decodeTarget(rt)
		if err != nil {
			return BackupParams{}, prefixErr(fmt.Sprintf("targets[%d]: ", i), err)
		}
		out.Targets = append(out.Targets, t)
	}
	if p.Tags != nil {
		if len(*p.Tags) > 20 {
			return BackupParams{}, invalid("tags must have at most 20 entries")
		}
		for _, t := range *p.Tags {
			if !tagRe.MatchString(t) {
				return BackupParams{}, invalid("tag %q not allowed", t)
			}
		}
		out.Tags = *p.Tags
	}
	if p.HelperImage != nil {
		if err := checkHelperImage(*p.HelperImage); err != nil {
			return BackupParams{}, err
		}
		out.HelperImage = *p.HelperImage
	}
	if p.Limits != nil {
		if p.Limits.TimeoutSec != nil {
			if *p.Limits.TimeoutSec < 60 || *p.Limits.TimeoutSec > 86400 {
				return BackupParams{}, invalid("limits.timeoutSec must be 60..86400")
			}
			out.Limits.TimeoutSec = *p.Limits.TimeoutSec
		}
		if p.Limits.UploadKiBps != nil {
			if *p.Limits.UploadKiBps < 0 || *p.Limits.UploadKiBps > 10_000_000 {
				return BackupParams{}, invalid("limits.uploadKiBps must be 0..10000000")
			}
			out.Limits.UploadKiBps = *p.Limits.UploadKiBps
		}
	}
	return out, nil
}

func prefixErr(prefix string, err error) error {
	if je, ok := err.(*jobs.Error); ok {
		return &jobs.Error{Code: je.Code, Message: prefix + je.Message, Details: je.Details}
	}
	return invalid("%s%v", prefix, err)
}

func decodeRepo(raw json.RawMessage) (RepoRef, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return RepoRef{}, invalid("repo is required")
	}
	var r RepoRef
	if err := containerops.DecodeParams(raw, &r); err != nil {
		return RepoRef{}, prefixErr("repo: ", err)
	}
	return r, r.validate()
}

// SnapshotsParams is backup.snapshots.
type SnapshotsParams struct {
	Repo RepoRef `json:"repo"`
	Tag  string  `json:"tag,omitempty"`
}

// DecodeSnapshots strictly decodes backup.snapshots params.
func DecodeSnapshots(raw json.RawMessage) (SnapshotsParams, error) {
	var p struct {
		Repo json.RawMessage `json:"repo"`
		Tag  *string         `json:"tag"`
	}
	if err := containerops.DecodeParams(raw, &p); err != nil {
		return SnapshotsParams{}, err
	}
	repo, err := decodeRepo(p.Repo)
	if err != nil {
		return SnapshotsParams{}, err
	}
	out := SnapshotsParams{Repo: repo}
	if p.Tag != nil {
		if !tagRe.MatchString(*p.Tag) {
			return SnapshotsParams{}, invalid("tag not allowed")
		}
		out.Tag = *p.Tag
	}
	return out, nil
}

// ManifestFile is one hashed file.
type ManifestFile struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	Sha256 string `json:"sha256"`
}

// TableCount is an exact row count of one table.
type TableCount struct {
	Name string `json:"name"`
	Rows int64  `json:"rows"`
}

// ManifestEntry is the manifest of one backed-up target (result
// `manifest[]`, stored by the Center, handed back to backup.verify /
// restore.run). Files are recorded for paths/volume targets; dump facts for DB
// targets.
type ManifestEntry struct {
	Target     int    `json:"target"`
	Type       string `json:"type"`
	SnapshotID string `json:"snapshotId"`
	// paths / volume
	Paths     []string       `json:"paths,omitempty"`
	App       string         `json:"app,omitempty"`
	Volume    string         `json:"volume,omitempty"`
	Files     []ManifestFile `json:"files,omitempty"`
	FileCount int            `json:"fileCount"`
	Truncated bool           `json:"truncated"`
	// postgres / mysql
	Database    string       `json:"database,omitempty"`
	Bytes       int64        `json:"bytes,omitempty"`
	Sha256      string       `json:"sha256,omitempty"`
	Tables      []TableCount `json:"tables,omitempty"`
	Constraints []string     `json:"constraints,omitempty"`
}

func (m *ManifestEntry) validate() error {
	if !targetTypes[m.Type] {
		return invalid("manifest: unknown type %q", m.Type)
	}
	if !snapshotRe.MatchString(m.SnapshotID) {
		return invalid("manifest: snapshotId must be a restic id")
	}
	if len(m.Files) > MaxManifestFiles || len(m.Tables) > MaxTables || len(m.Constraints) > MaxConstraints {
		return invalid("manifest: too many entries")
	}
	for _, f := range m.Files {
		// every manifest path (host path or /backup/<volume>/...) must be canonical:
		// a "/backup/" prefix is NOT an exemption ("/backup/../etc/shadow").
		if CheckHostPath(f.Path) != nil {
			return invalid("manifest: file path %q not allowed", f.Path)
		}
		if !sha256HexRe.MatchString(f.Sha256) || f.Size < 0 {
			return invalid("manifest: file %q needs size and sha256", f.Path)
		}
	}
	if m.Sha256 != "" && !sha256HexRe.MatchString(m.Sha256) {
		return invalid("manifest: sha256 must be 64 hex")
	}
	for _, t := range m.Tables {
		if !tableNameRe.MatchString(t.Name) || t.Rows < 0 {
			return invalid("manifest: table %q invalid", t.Name)
		}
	}
	return nil
}

// decodeManifest accepts one entry (object) or the full run manifest (array).
func decodeManifest(raw json.RawMessage) ([]ManifestEntry, error) {
	t := bytes.TrimSpace(raw)
	if len(t) == 0 {
		return nil, nil
	}
	var items []json.RawMessage
	if t[0] == '[' {
		if err := json.Unmarshal(t, &items); err != nil {
			return nil, invalid("manifest: %v", err)
		}
	} else {
		items = []json.RawMessage{t}
	}
	if len(items) > 20 {
		return nil, invalid("manifest: at most 20 entries")
	}
	out := make([]ManifestEntry, 0, len(items))
	for _, it := range items {
		var m ManifestEntry
		if err := jobs.DecodeStrict(it, &m); err != nil {
			return nil, invalid("manifest: %v", err)
		}
		if err := m.validate(); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, nil
}

// FindManifest returns the entry for snapshotID (full or short id match).
func FindManifest(ms []ManifestEntry, snapshotID string) *ManifestEntry {
	for i := range ms {
		id := ms[i].SnapshotID
		if id == snapshotID || strings.HasPrefix(id, snapshotID) || strings.HasPrefix(snapshotID, id) {
			return &ms[i]
		}
	}
	return nil
}

// VerifyParams is backup.verify.
type VerifyParams struct {
	Repo              RepoRef         `json:"repo"`
	SnapshotID        string          `json:"snapshotId"`
	ReadDataSubsetPct int             `json:"readDataSubsetPct"`
	Manifest          []ManifestEntry `json:"manifest,omitempty"`
}

// DecodeVerify strictly decodes backup.verify params. `manifest` (optional) is
// the snapshot's manifest as returned by backup.run (one entry or the array).
func DecodeVerify(raw json.RawMessage) (VerifyParams, error) {
	var p struct {
		Repo              json.RawMessage `json:"repo"`
		SnapshotID        string          `json:"snapshotId"`
		ReadDataSubsetPct *int            `json:"readDataSubsetPct"`
		Manifest          json.RawMessage `json:"manifest"`
	}
	if err := containerops.DecodeParams(raw, &p); err != nil {
		return VerifyParams{}, err
	}
	repo, err := decodeRepo(p.Repo)
	if err != nil {
		return VerifyParams{}, err
	}
	if !snapshotRe.MatchString(p.SnapshotID) {
		return VerifyParams{}, invalid("snapshotId must be a restic snapshot id")
	}
	out := VerifyParams{Repo: repo, SnapshotID: p.SnapshotID, ReadDataSubsetPct: 5}
	if p.ReadDataSubsetPct != nil {
		if *p.ReadDataSubsetPct < 0 || *p.ReadDataSubsetPct > 100 {
			return VerifyParams{}, invalid("readDataSubsetPct must be 0..100")
		}
		out.ReadDataSubsetPct = *p.ReadDataSubsetPct
	}
	if out.Manifest, err = decodeManifest(p.Manifest); err != nil {
		return VerifyParams{}, err
	}
	return out, nil
}

// RestoreTarget is restoreTargetSchema.
type RestoreTarget struct {
	Target
	Include      []string `json:"include,omitempty"`
	Mode         string   `json:"mode"`
	ScratchImage string   `json:"scratchImage,omitempty"`
}

func decodeRestoreTarget(raw json.RawMessage) (RestoreTarget, error) {
	typ, err := peekType(raw)
	if err != nil {
		return RestoreTarget{}, err
	}
	var rt RestoreTarget
	switch typ {
	case "paths":
		var p struct {
			Type    string    `json:"type"`
			Include *[]string `json:"include"`
			Mode    string    `json:"mode"`
		}
		if err := containerops.DecodeParams(raw, &p); err != nil {
			return RestoreTarget{}, err
		}
		rt = RestoreTarget{Target: Target{Type: typ}, Include: []string{}, Mode: p.Mode}
		if p.Include != nil {
			if len(*p.Include) > 50 {
				return RestoreTarget{}, invalid("include must have at most 50 entries")
			}
			for _, x := range *p.Include {
				if err := CheckHostPath(x); err != nil {
					return RestoreTarget{}, invalid("%v", err)
				}
			}
			rt.Include = *p.Include
		}
		if rt.Mode == "in_place" && len(rt.Include) == 0 {
			return RestoreTarget{}, invalid("paths in_place restore needs a non-empty include list")
		}
	case "volume":
		var p struct {
			Type   string `json:"type"`
			App    string `json:"app"`
			Volume string `json:"volume"`
			Mode   string `json:"mode"`
		}
		if err := containerops.DecodeParams(raw, &p); err != nil {
			return RestoreTarget{}, err
		}
		if err := checkApp(p.App); err != nil {
			return RestoreTarget{}, err
		}
		if !volumeRe.MatchString(p.Volume) {
			return RestoreTarget{}, invalid("volume must match %s", volumeRe)
		}
		rt = RestoreTarget{Target: Target{Type: typ, App: p.App, Volume: p.Volume}, Mode: p.Mode}
	default:
		var p struct {
			Type              string  `json:"type"`
			App               string  `json:"app"`
			Service           string  `json:"service"`
			Database          string  `json:"database"`
			User              string  `json:"user"`
			PasswordSecretKey string  `json:"passwordSecretKey"`
			Mode              string  `json:"mode"`
			ScratchImage      *string `json:"scratchImage"`
		}
		if err := containerops.DecodeParams(raw, &p); err != nil {
			return RestoreTarget{}, err
		}
		if err := checkApp(p.App); err != nil {
			return RestoreTarget{}, err
		}
		if err := checkDBFields(p.Service, p.Database, p.User, p.PasswordSecretKey, 0); err != nil {
			return RestoreTarget{}, err
		}
		rt = RestoreTarget{Target: Target{Type: typ, App: p.App, Service: p.Service, Database: p.Database, User: p.User,
			PasswordSecretKey: p.PasswordSecretKey}, Mode: p.Mode}
		if p.ScratchImage != nil {
			if len(*p.ScratchImage) > 400 || !containerops.ImageDigestRefRe.MatchString(*p.ScratchImage) {
				return RestoreTarget{}, invalid("scratchImage must be pinned by digest")
			}
			rt.ScratchImage = *p.ScratchImage
		}
	}
	if !restoreModes[typ][rt.Mode] {
		return RestoreTarget{}, invalid("mode %q is not valid for a %s restore", rt.Mode, typ)
	}
	return rt, nil
}

// RestoreParams is restore.run.
type RestoreParams struct {
	RestoreID   string          `json:"restoreId"`
	Repo        RepoRef         `json:"repo"`
	SnapshotID  string          `json:"snapshotId"`
	Target      RestoreTarget   `json:"target"`
	DryRun      bool            `json:"dryRun"`
	HelperImage string          `json:"helperImage,omitempty"`
	Verify      bool            `json:"verify"`
	TimeoutSec  int             `json:"timeoutSec"`
	Manifest    []ManifestEntry `json:"manifest,omitempty"`
}

// DecodeRestore strictly decodes restore.run params. `manifest` (optional,
// agent extension) is the snapshot's manifest for the verify compare.
func DecodeRestore(raw json.RawMessage) (RestoreParams, error) {
	var p struct {
		RestoreID   string          `json:"restoreId"`
		Repo        json.RawMessage `json:"repo"`
		SnapshotID  string          `json:"snapshotId"`
		Target      json.RawMessage `json:"target"`
		DryRun      *bool           `json:"dryRun"`
		HelperImage *string         `json:"helperImage"`
		Verify      *bool           `json:"verify"`
		TimeoutSec  *int            `json:"timeoutSec"`
		Manifest    json.RawMessage `json:"manifest"`
	}
	if err := containerops.DecodeParams(raw, &p); err != nil {
		return RestoreParams{}, err
	}
	if !containerops.UUIDRe.MatchString(p.RestoreID) {
		return RestoreParams{}, invalid("restoreId must be a uuid")
	}
	repo, err := decodeRepo(p.Repo)
	if err != nil {
		return RestoreParams{}, err
	}
	if !snapshotRe.MatchString(p.SnapshotID) {
		return RestoreParams{}, invalid("snapshotId must be a restic snapshot id")
	}
	if len(bytes.TrimSpace(p.Target)) == 0 {
		return RestoreParams{}, invalid("target is required")
	}
	rt, err := decodeRestoreTarget(p.Target)
	if err != nil {
		return RestoreParams{}, prefixErr("target: ", err)
	}
	out := RestoreParams{RestoreID: strings.ToLower(p.RestoreID), Repo: repo, SnapshotID: p.SnapshotID, Target: rt, Verify: true, TimeoutSec: 3600}
	if p.DryRun != nil {
		out.DryRun = *p.DryRun
	}
	if p.Verify != nil {
		out.Verify = *p.Verify
	}
	if p.HelperImage != nil {
		if err := checkHelperImage(*p.HelperImage); err != nil {
			return RestoreParams{}, err
		}
		out.HelperImage = *p.HelperImage
	}
	if p.TimeoutSec != nil {
		if *p.TimeoutSec < 60 || *p.TimeoutSec > 86400 {
			return RestoreParams{}, invalid("timeoutSec must be 60..86400")
		}
		out.TimeoutSec = *p.TimeoutSec
	}
	if out.Manifest, err = decodeManifest(p.Manifest); err != nil {
		return RestoreParams{}, err
	}
	return out, nil
}

// UnderDir reports whether p is dir or inside it (both clean absolute).
func UnderDir(p, dir string) bool {
	if dir == "" || dir == "/" {
		return false
	}
	return p == dir || strings.HasPrefix(p, strings.TrimSuffix(dir, "/")+"/")
}
