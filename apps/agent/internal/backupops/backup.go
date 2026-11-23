package backupops

import (
	"context"
	"errors"
	"os"
	"path"
	"strings"
	"time"

	"github.com/ppanel/ppanel/apps/agent/internal/containerops"
	"github.com/ppanel/ppanel/apps/agent/internal/docker"
	"github.com/ppanel/ppanel/apps/agent/internal/jobs"
)

// SnapshotResult is one backup.run `snapshots[]` entry.
type SnapshotResult struct {
	Target       int    `json:"target"`
	Type         string `json:"type"`
	SnapshotID   string `json:"snapshotId"`
	ShortID      string `json:"shortId"`
	SizeBytes    int64  `json:"sizeBytes"`
	FilesNew     int64  `json:"filesNew"`
	FilesChanged int64  `json:"filesChanged"`
	DurationMs   int64  `json:"durationMs"`
}

// TargetFailure is one failed target (BACKUP_PARTIAL / BACKUP_FAILED details).
type TargetFailure struct {
	Target  int    `json:"target"`
	Type    string `json:"type"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

// BackupOutput is the backup.run success output.
type BackupOutput struct {
	Snapshots     []SnapshotResult `json:"snapshots"`
	Manifest      []ManifestEntry  `json:"manifest"`
	ResticVersion string           `json:"resticVersion"`
}

func appsOf(ts []Target) []string {
	var apps []string
	for _, t := range ts {
		if t.App != "" {
			apps = append(apps, t.App)
		}
	}
	return apps
}

// Backup implements backup.run. Every target runs (unless the run is
// aborted); a run that does not finish ALL targets is a failure:
// BACKUP_PARTIAL (some snapshots created) or BACKUP_FAILED / a specific code
// (none created). It never prunes or forgets anything.
func (m *Manager) Backup(ctx context.Context, p BackupParams) (any, error) {
	if err := m.PreflightBackup(p); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(p.Limits.TimeoutSec)*time.Second)
	defer cancel()
	release, err := m.lock(ctx, p.Repo.RepositoryID, appsOf(p.Targets))
	if err != nil {
		return nil, err
	}
	defer release()
	log := m.o.Log.With("job", "backup.run", "runId", p.RunID)
	s, err := m.newSession(ctx, p.Repo, log)
	if err != nil {
		return nil, err
	}
	if p.NeedsHelper() {
		if err := s.prepareHelper(p.HelperImage); err != nil {
			return nil, s.redactErr(err)
		}
	}
	out := BackupOutput{Snapshots: []SnapshotResult{}, Manifest: []ManifestEntry{}, ResticVersion: m.o.ResticVersion}
	var failures []TargetFailure
	budget := NewBudget()
	for i, t := range p.Targets {
		if ctx.Err() != nil {
			failures = append(failures, TargetFailure{Target: i, Type: t.Type, Code: CodeBackupFailed, Message: abortedErr(ctx, "run").Message})
			continue
		}
		start := time.Now()
		var snap *SnapshotResult
		var man *ManifestEntry
		var terr error
		switch {
		case t.Type == "paths":
			snap, man, terr = s.backupPaths(p, i, t, budget)
		case t.Type == "volume":
			snap, man, terr = s.backupVolume(p, i, t, budget)
		default:
			snap, man, terr = s.backupDB(p, i, t)
		}
		if terr != nil {
			je := toJobErr(terr)
			log.Warn("backup target failed", "target", i, "type", t.Type, "code", je.Code)
			failures = append(failures, TargetFailure{Target: i, Type: t.Type, Code: je.Code, Message: s.redact(je.Message)})
			continue
		}
		snap.DurationMs = time.Since(start).Milliseconds()
		out.Snapshots = append(out.Snapshots, *snap)
		out.Manifest = append(out.Manifest, *man)
		log.Info("backup target done", "target", i, "type", t.Type, "snapshot", snap.ShortID)
	}
	if len(failures) == 0 {
		return s.redactOut(out)
	}
	details := map[string]any{"snapshots": out.Snapshots, "manifest": out.Manifest, "failures": failures,
		"completedTargets": completed(out.Snapshots), "resticVersion": m.o.ResticVersion}
	var e *jobs.Error
	if len(out.Snapshots) > 0 {
		e = jerr(CodeBackupPartial, "%d of %d targets failed; the run is NOT complete", len(failures), len(p.Targets))
	} else {
		code := failures[0].Code
		for _, f := range failures {
			if f.Code != code {
				code = CodeBackupFailed
			}
		}
		if code == jobs.HandlerFailed {
			code = CodeBackupFailed
		}
		e = jerr(code, "backup failed: %s", failures[0].Message)
	}
	e.Details = details
	return nil, s.redactErr(e)
}

func completed(ss []SnapshotResult) []int {
	out := []int{}
	for _, s := range ss {
		out = append(out, s.Target)
	}
	return out
}

func toJobErr(err error) *jobs.Error {
	var je *jobs.Error
	if errors.As(err, &je) {
		return je
	}
	return jerr(CodeBackupFailed, "%v", err)
}

func snapFrom(i int, typ string, sum *BackupSummary) *SnapshotResult {
	short := sum.SnapshotID
	if len(short) > 8 {
		short = short[:8]
	}
	return &SnapshotResult{Target: i, Type: typ, SnapshotID: sum.SnapshotID, ShortID: short, SizeBytes: sum.TotalBytesProcessed,
		FilesNew: sum.FilesNew, FilesChanged: sum.FilesChanged}
}

// resticResultErr maps a finished restic run (host or helper) to an error.
func (s *session) resticResultErr(what string, exit int, stdout, stderr []byte, def string) error {
	text := failureText(stdout, stderr)
	if exit == 3 {
		return jerr(CodeBackupFailed, "%s: snapshot incomplete (restic exit 3: some source files could not be read): %s", what, text)
	}
	return jerr(ClassifyFailure(exit, text, def), "%s: restic exited %d: %s", what, exit, text)
}

func (s *session) backupPaths(p BackupParams, i int, t Target, budget *Budget) (*SnapshotResult, *ManifestEntry, error) {
	for _, x := range t.Paths {
		if _, err := os.Lstat(x); err != nil {
			return nil, nil, jerr(CodeBackupFailed, "path %s does not exist or is not accessible", x)
		}
	}
	excludes := append([]string{}, t.Excludes...)
	if s.m.o.StateDir != "" {
		excludes = append(excludes, s.m.o.StateDir)
	}
	// manifest hashed from the source while restic runs
	type hashed struct {
		files     []ManifestFile
		truncated bool
	}
	hch := make(chan hashed, 1)
	go func() {
		f, tr, _ := HashPaths(s.ctx, t.Paths, s.m.o.StateDir, budget)
		hch <- hashed{f, tr}
	}()
	res, err := s.restic(BackupArgs(p, i, false, "", excludes, "", t.Paths), 8<<20)
	h := <-hch
	if err != nil {
		if s.ctx.Err() != nil {
			return nil, nil, abortedErr(s.ctx, "paths backup")
		}
		return nil, nil, jerr(CodeBackupFailed, "restic backup: %v", err)
	}
	if res.ExitCode != 0 {
		return nil, nil, s.resticResultErr("paths backup", res.ExitCode, res.Stdout, res.Stderr, CodeBackupFailed)
	}
	sum, err := ParseSummary(res.Stdout)
	if err != nil {
		return nil, nil, jerr(CodeBackupFailed, "paths backup: %v", err)
	}
	if h.files == nil {
		h.files = []ManifestFile{}
	}
	man := &ManifestEntry{Target: i, Type: "paths", SnapshotID: sum.SnapshotID, Paths: t.Paths, Files: h.files,
		FileCount: len(h.files), Truncated: h.truncated}
	return snapFrom(i, "paths", sum), man, nil
}

// ownedVolume checks the managed volume of app exists and carries pPanel labels.
func (s *session) ownedVolume(name, app string) error {
	vi, err := s.m.o.Engine.InspectVolume(s.ctx, name)
	if errors.Is(err, docker.ErrNotFound) {
		return jerr(CodeBackupFailed, "volume %s not found", name)
	}
	if err != nil {
		return s.dockerErr("inspect volume", err)
	}
	if vi.Labels[containerops.LabelManaged] != "true" || vi.Labels[containerops.LabelApp] != app {
		return jerr(containerops.CodeContainerNotManaged, "volume %s is not managed by pPanel for app %s", name, app)
	}
	return nil
}

func (s *session) ownedNetwork(app string) error {
	name := containerops.NetworkName(app)
	n, err := s.m.o.Engine.InspectNetwork(s.ctx, name)
	if errors.Is(err, docker.ErrNotFound) {
		return jerr(CodeDumpFailed, "app network %s not found", name)
	}
	if err != nil {
		return s.dockerErr("inspect network", err)
	}
	if n.Labels[containerops.LabelManaged] != "true" {
		return jerr(containerops.CodeContainerNotManaged, "network %s is not managed by pPanel", name)
	}
	return nil
}

// volumeTarName maps a docker archive entry of /backup/<vol> ("<vol>/x") to
// the snapshot path "/backup/<vol>/x".
func volumeTarName(vol string) func(string) string {
	return func(n string) string {
		if n == "/"+vol || strings.HasPrefix(n, "/"+vol+"/") {
			return "/backup" + n
		}
		return ""
	}
}

func (s *session) backupVolume(p BackupParams, i int, t Target, budget *Budget) (*SnapshotResult, *ManifestEntry, error) {
	vol := t.VolumeName()
	if err := s.ownedVolume(vol, t.App); err != nil {
		return nil, nil, err
	}
	src := "/backup/" + t.Volume
	spec := s.helper("backup", t.App, p.RunID, BackupArgs(p, i, true, s.m.o.Hostname, nil, "", []string{src}), nil)
	spec.Mounts = []Mount{{Volume: vol, Target: src, ReadOnly: true}}
	// root inside the helper, but only to READ every file of the volume
	spec.User = "0"
	spec.CapAdd = []string{"DAC_READ_SEARCH"}
	var files []ManifestFile
	var truncated bool
	res, err := s.runHelper(spec, func(h *helperRun, r *HelperResult) error {
		if r.ExitCode != 0 {
			return nil
		}
		rc, err := h.archive(s.ctx, src)
		if err != nil {
			return s.dockerErr("read volume for manifest", err)
		}
		defer rc.Close()
		files, truncated, err = HashTar(rc, volumeTarName(t.Volume), budget)
		if err != nil {
			return jerr(CodeBackupFailed, "manifest: %v", err)
		}
		return nil
	})
	if err != nil {
		if s.ctx.Err() != nil {
			return nil, nil, abortedErr(s.ctx, "volume backup")
		}
		return nil, nil, s.dockerErr("volume backup helper", err)
	}
	if res.ExitCode != 0 {
		return nil, nil, s.resticResultErr("volume backup", res.ExitCode, res.Stdout, res.Stderr, CodeBackupFailed)
	}
	sum, err := ParseSummary(res.Stdout)
	if err != nil {
		return nil, nil, jerr(CodeBackupFailed, "volume backup: %v", err)
	}
	if files == nil {
		files = []ManifestFile{}
	}
	man := &ManifestEntry{Target: i, Type: "volume", SnapshotID: sum.SnapshotID, App: t.App, Volume: t.Volume,
		Paths: []string{src}, Files: files, FileCount: len(files), Truncated: truncated}
	return snapFrom(i, "volume", sum), man, nil
}

// dbConn is how a helper reaches a database.
type dbConn struct {
	Type     string
	Host     string
	Port     int
	User     string
	Password string
	Database string
	Network  string
	App      string
	Label    string
}

func (c dbConn) passwordEnv() string {
	if c.Type == "mysql" {
		return "MYSQL_PWD=" + c.Password
	}
	return "PGPASSWORD=" + c.Password
}

// DumpCommand is the dump argv restic runs via --stdin-from-command.
func DumpCommand(c dbConn) []string {
	if c.Type == "mysql" {
		return []string{"mysqldump", "--single-transaction", "--routines", "--triggers", "--host=" + c.Host,
			"--port=" + fmtPort(c.Port), "--user=" + c.User, c.Database}
	}
	return []string{"pg_dump", "--no-password", "--format=plain", "--clean", "--if-exists", "--host=" + c.Host,
		"--port=" + fmtPort(c.Port), "--username=" + c.User, "--dbname=" + c.Database}
}

func (s *session) appConn(t Target, label string) (dbConn, error) {
	pw, ok := s.env[t.PasswordSecretKey]
	if !ok {
		return dbConn{}, jerr(containerops.CodeSecretsUnavailable, "secret %s not delivered", t.PasswordSecretKey)
	}
	return dbConn{Type: t.Type, Host: t.Service, Port: t.DefaultPort(), User: t.User, Password: pw, Database: t.Database,
		Network: containerops.NetworkName(t.App), App: t.App, Label: label}, nil
}

func (s *session) backupDB(p BackupParams, i int, t Target) (*SnapshotResult, *ManifestEntry, error) {
	c, err := s.appConn(t, p.RunID)
	if err != nil {
		return nil, nil, err
	}
	if err := s.ownedNetwork(t.App); err != nil {
		return nil, nil, err
	}
	spec := s.helper("backup", t.App, p.RunID, BackupArgs(p, i, true, s.m.o.Hostname, nil, t.DumpFile(), DumpCommand(c)),
		[]string{c.passwordEnv()})
	spec.Network = c.Network
	res, err := s.runHelper(spec, nil)
	if err != nil {
		if s.ctx.Err() != nil {
			return nil, nil, abortedErr(s.ctx, "dump backup")
		}
		return nil, nil, s.dockerErr("dump helper", err)
	}
	if res.ExitCode != 0 {
		text := failureText(res.Stdout, res.Stderr)
		if strings.Contains(text, "command failed") || strings.Contains(text, "pg_dump") || strings.Contains(text, "mysqldump") {
			return nil, nil, jerr(CodeDumpFailed, "%s dump of %s failed: %s", t.Type, t.Database, text)
		}
		return nil, nil, s.resticResultErr("dump backup", res.ExitCode, res.Stdout, res.Stderr, CodeDumpFailed)
	}
	sum, err := ParseSummary(res.Stdout)
	if err != nil {
		return nil, nil, jerr(CodeDumpFailed, "dump backup: %v", err)
	}
	// manifest: dump stream hash (read back from the repo) + exact row counts
	sha, size, _, err := s.fetchDump(sum.SnapshotID, t.App, p.RunID, t.DumpFile(), nil)
	if err != nil {
		return nil, nil, jerr(CodeBackupFailed, "manifest (dump hash) for snapshot %s: %s", sum.SnapshotID[:8], toJobErr(err).Message)
	}
	tables, cons, err := s.queryDB(c)
	if err != nil {
		return nil, nil, jerr(CodeBackupFailed, "manifest (row counts) for snapshot %s: %s", sum.SnapshotID[:8], toJobErr(err).Message)
	}
	man := &ManifestEntry{Target: i, Type: t.Type, SnapshotID: sum.SnapshotID, App: t.App, Database: t.Database,
		Bytes: size, Sha256: sha, Tables: tables, Constraints: cons, Paths: []string{"/" + t.DumpFile()}}
	return snapFrom(i, t.Type, sum), man, nil
}

// fetchDump runs `restic dump --target /work/<file> <snap> /<file>` in a
// helper and streams the file back to hash it (and scan its lines). keep, if
// set, runs while the helper still exists (dump hand-off to a load helper).
func (s *session) fetchDump(snap, app, label, file string, onLine func(string), keep ...func(*helperRun) error) (string, int64, *HelperResult, error) {
	dst := path.Join(HelperWorkDir, file)
	cmd := []string{"--no-cache", "-r", s.repo.ResticURL(), "dump", "--target", dst, snap, "/" + file}
	spec := s.helper("dump", app, label, cmd, nil)
	spec.Writable = true
	var sha string
	var size int64
	res, err := s.runHelper(spec, func(h *helperRun, r *HelperResult) error {
		if r.ExitCode != 0 {
			return nil
		}
		rc, err := h.archive(s.ctx, dst)
		if err != nil {
			return s.dockerErr("read dump", err)
		}
		sha, size, err = HashSingleFromTar(rc, onLine)
		rc.Close()
		if err != nil {
			return jerr(CodeRestoreFailed, "read dump: %v", err)
		}
		for _, k := range keep {
			if err := k(h); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		if s.ctx.Err() != nil {
			return "", 0, nil, abortedErr(s.ctx, "dump fetch")
		}
		return "", 0, res, err
	}
	if res.ExitCode != 0 {
		return "", 0, res, s.resticResultErr("restic dump", res.ExitCode, res.Stdout, res.Stderr, CodeRestoreFailed)
	}
	return sha, size, res, nil
}

var _ = context.Background
