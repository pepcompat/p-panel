package backupops

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ppanel/ppanel/apps/agent/internal/containerops"
	"github.com/ppanel/ppanel/apps/agent/internal/docker"
	"github.com/ppanel/ppanel/apps/agent/internal/jobs"
)

// VerifyResult is restore.run `verify` (and the backup.verify compare).
type VerifyResult struct {
	OK         bool       `json:"ok"`
	Compared   int        `json:"compared"`
	Mismatches []Mismatch `json:"mismatches"`
	// Method: manifest (compared with the backup manifest) | restic (restic
	// restore --verify re-read only; no manifest supplied) | none.
	Method string `json:"method"`
}

// RestoredItem is one restore.run `restored[]` entry.
type RestoredItem struct {
	Type          string   `json:"type"`
	SnapshotID    string   `json:"snapshotId"`
	Mode          string   `json:"mode"`
	FilesRestored int64    `json:"filesRestored,omitempty"`
	BytesRestored int64    `json:"bytesRestored,omitempty"`
	Include       []string `json:"include,omitempty"`
	Database      string   `json:"database,omitempty"`
	DumpBytes     int64    `json:"dumpBytes,omitempty"`
	DumpSha256    string   `json:"dumpSha256,omitempty"`
}

// ScratchInfo is restore.run `scratch`.
type ScratchInfo struct {
	Container string `json:"container"`
	Network   string `json:"network"`
	Image     string `json:"image"`
	Removed   bool   `json:"removed"`
}

// DryRunInfo is restore.run `dryRun` (nothing was written).
type DryRunInfo struct {
	Items      []DryRunItem `json:"items,omitempty"`
	ItemCount  int          `json:"itemCount"`
	TotalFiles int64        `json:"totalFiles,omitempty"`
	TotalBytes int64        `json:"totalBytes,omitempty"`
	DumpBytes  int64        `json:"dumpBytes,omitempty"`
	DumpSha256 string       `json:"dumpSha256,omitempty"`
	Tables     []string     `json:"tables,omitempty"`
	TargetPath string       `json:"targetPath,omitempty"`
	Volume     string       `json:"volume,omitempty"`
}

// DryRunItem is one restic dry-run listing entry.
type DryRunItem struct {
	Action string `json:"action"`
	Item   string `json:"item"`
	Size   int64  `json:"size"`
}

// RestoreOutput is the restore.run output.
type RestoreOutput struct {
	RestoreID   string         `json:"restoreId"`
	DryRun      bool           `json:"dryRun"`
	Restored    []RestoredItem `json:"restored"`
	Verify      *VerifyResult  `json:"verify,omitempty"`
	StagingPath string         `json:"stagingPath,omitempty"`
	Volume      string         `json:"volume,omitempty"`
	Scratch     *ScratchInfo   `json:"scratch,omitempty"`
	Tables      []TableCount   `json:"tables,omitempty"`
	Constraints []string       `json:"constraints,omitempty"`
	Plan        *DryRunInfo    `json:"plan,omitempty"`
}

// MaxDryRunItems bounds the dry-run listing.
const MaxDryRunItems = 1000

// StagingDir is where a paths staging restore goes.
func (m *Manager) StagingDir(restoreID string) string {
	return filepath.Join(m.o.StateDir, "restores", restoreID)
}

func restoreArgs(repo RepoRef, snap string, noCache bool, target string, includes []string, dryRun, verify, del bool) []string {
	var a []string
	if noCache {
		a = append(a, "--no-cache")
	}
	a = append(a, "-r", repo.ResticURL(), "restore", snap, "--target", target, "--json")
	for _, i := range includes {
		a = append(a, "--include", i)
	}
	if dryRun {
		a = append(a, "--dry-run", "-vv")
	} else if verify {
		a = append(a, "--verify")
	}
	if del {
		a = append(a, "--delete")
	}
	return a
}

func dryRunFrom(p ParsedOutput) *DryRunInfo {
	d := &DryRunInfo{ItemCount: p.ItemCount, Items: []DryRunItem{}}
	for _, it := range p.Items {
		d.Items = append(d.Items, DryRunItem{Action: it.Action, Item: it.Item, Size: it.Size})
	}
	if p.Restore != nil {
		d.TotalFiles, d.TotalBytes = p.Restore.TotalFiles, p.Restore.TotalBytes
	}
	return d
}

// Restore implements restore.run.
func (m *Manager) Restore(ctx context.Context, p RestoreParams) (any, error) {
	if err := m.PreflightRestore(p); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(p.TimeoutSec)*time.Second)
	defer cancel()
	var apps []string
	if p.Target.App != "" {
		apps = []string{p.Target.App}
	}
	release, err := m.lock(ctx, p.Repo.RepositoryID, apps)
	if err != nil {
		return nil, err
	}
	defer release()
	log := m.o.Log.With("job", "restore.run", "restoreId", p.RestoreID, "type", p.Target.Type, "mode", p.Target.Mode, "dryRun", p.DryRun)
	s, err := m.newSession(ctx, p.Repo, log)
	if err != nil {
		return nil, err
	}
	if p.Target.NeedsHelper() {
		if err := s.prepareHelper(p.HelperImage); err != nil {
			return nil, s.redactErr(err)
		}
	}
	var out *RestoreOutput
	switch p.Target.Type {
	case "paths":
		out, err = s.restorePaths(p)
	case "volume":
		out, err = s.restoreVolume(p)
	default:
		out, err = s.restoreDB(p)
	}
	if err != nil {
		return nil, s.redactErr(err)
	}
	out.RestoreID, out.DryRun = p.RestoreID, p.DryRun
	if out.Restored == nil {
		out.Restored = []RestoredItem{}
	}
	if out.Verify != nil && !out.Verify.OK {
		e := jerr(CodeVerifyFailed, "restore verification failed: %d mismatches", len(out.Verify.Mismatches))
		e.Details = out
		return nil, s.redactErr(e)
	}
	log.Info("restore finished")
	return s.redactOut(out)
}

// verifyFiles hashes root+path for each expected manifest file under includes.
func verifyFiles(expected []ManifestFile, root string, includes []string) VerifyResult {
	actual := map[string]ManifestFile{}
	keep := func(p string) bool { return underAny(p, includes) }
	for _, e := range expected {
		if !keep(e.Path) {
			continue
		}
		if sha, sz, err := hashFile(filepath.Join(root, e.Path)); err == nil {
			actual[e.Path] = ManifestFile{Path: e.Path, Size: sz, Sha256: sha}
		}
	}
	n, mm := CompareFiles(expected, actual, func(p string) string { return p }, keep)
	if mm == nil {
		mm = []Mismatch{}
	}
	return VerifyResult{OK: len(mm) == 0, Compared: n, Mismatches: mm, Method: "manifest"}
}

func (s *session) restorePaths(p RestoreParams) (*RestoreOutput, error) {
	t := p.Target
	target := "/"
	out := &RestoreOutput{}
	if t.Mode == "staging" {
		target = s.m.StagingDir(p.RestoreID)
		if _, err := os.Lstat(target); err == nil {
			return nil, jerr(CodeRestoreTargetExists, "staging directory for restore %s already exists", p.RestoreID)
		}
		out.StagingPath = target
	}
	if p.DryRun {
		res, err := s.restic(restoreArgs(p.Repo, p.SnapshotID, false, target, t.Include, true, false, false), 16<<20)
		if err != nil {
			return nil, jerr(CodeRestoreFailed, "restic restore --dry-run: %v", err)
		}
		if res.ExitCode != 0 {
			return nil, s.resticResultErr("restore dry-run", res.ExitCode, res.Stdout, res.Stderr, CodeRestoreFailed)
		}
		out.Plan = dryRunFrom(ParseJSONLines(res.Stdout, MaxDryRunItems))
		out.Plan.TargetPath = target
		return out, nil
	}
	if t.Mode == "staging" {
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			return nil, jerr(CodeRestoreFailed, "create restores dir: %v", err)
		}
		if err := os.Mkdir(target, 0o700); err != nil {
			if errors.Is(err, os.ErrExist) {
				return nil, jerr(CodeRestoreTargetExists, "staging directory for restore %s already exists", p.RestoreID)
			}
			return nil, jerr(CodeRestoreFailed, "create staging dir: %v", err)
		}
		_ = os.Chmod(target, 0o700)
	}
	res, err := s.restic(restoreArgs(p.Repo, p.SnapshotID, false, target, t.Include, false, p.Verify, false), 8<<20)
	if err != nil {
		if s.ctx.Err() != nil {
			return nil, jerr(CodeRestoreFailed, "restore aborted (%s)", timeLeft(s.ctx))
		}
		return nil, jerr(CodeRestoreFailed, "restic restore: %v", err)
	}
	if res.ExitCode != 0 {
		return nil, s.resticResultErr("restore", res.ExitCode, res.Stdout, res.Stderr, CodeRestoreFailed)
	}
	po := ParseJSONLines(res.Stdout, 0)
	item := RestoredItem{Type: "paths", SnapshotID: p.SnapshotID, Mode: t.Mode, Include: t.Include}
	if po.Restore != nil {
		item.FilesRestored, item.BytesRestored = po.Restore.FilesRestored, po.Restore.BytesRestored
	}
	out.Restored = []RestoredItem{item}
	if p.Verify {
		root := ""
		if t.Mode == "staging" {
			root = target
		}
		if man := FindManifest(p.Manifest, p.SnapshotID); man != nil {
			v := verifyFiles(man.Files, root, t.Include)
			out.Verify = &v
		} else {
			out.Verify = &VerifyResult{OK: true, Compared: int(item.FilesRestored), Mismatches: []Mismatch{}, Method: "restic"}
		}
	}
	return out, nil
}

func (s *session) restoreVolume(p RestoreParams) (*RestoreOutput, error) {
	t := p.Target
	e := s.m.o.Engine
	out := &RestoreOutput{}
	src := p.SnapshotID + ":/backup/" + t.Volume
	var vol string
	if t.Mode == "in_place" {
		vol = t.VolumeName()
		if err := s.ownedVolume(vol, t.App); err != nil {
			return nil, err
		}
	} else {
		vol = containerops.VolumeName(t.App, "restore-"+randHex(4))
	}
	if p.DryRun {
		spec := s.helper("restore", t.App, p.RestoreID, restoreArgs(p.Repo, src, true, "/restore", nil, true, false, t.Mode == "in_place"), nil)
		if t.Mode == "in_place" {
			spec.Mounts = []Mount{{Volume: vol, Target: "/restore", ReadOnly: true}}
			spec.User, spec.CapAdd = "0", []string{"DAC_READ_SEARCH"}
		}
		res, err := s.runHelper(spec, nil)
		if err != nil {
			return nil, s.dockerErr("restore dry-run helper", err)
		}
		if res.ExitCode != 0 {
			return nil, s.resticResultErr("volume restore dry-run", res.ExitCode, res.Stdout, res.Stderr, CodeRestoreFailed)
		}
		out.Plan = dryRunFrom(ParseJSONLines(res.Stdout, MaxDryRunItems))
		out.Plan.Volume = vol
		return out, nil
	}
	if t.Mode == "staging" {
		vi, err := e.CreateVolume(s.ctx, vol, map[string]string{containerops.LabelManaged: "true", containerops.LabelApp: t.App,
			LabelBackup: p.RestoreID, LabelRole: "restore"})
		if err != nil {
			return nil, s.dockerErr("create restore volume", err)
		}
		if vi.Labels[LabelBackup] != p.RestoreID {
			return nil, jerr(CodeRestoreTargetExists, "restore volume %s already exists", vol)
		}
	}
	out.Volume = vol
	spec := s.helper("restore", t.App, p.RestoreID, restoreArgs(p.Repo, src, true, "/restore", nil, false, p.Verify, t.Mode == "in_place"), nil)
	spec.Mounts = []Mount{{Volume: vol, Target: "/restore", ReadOnly: false}}
	spec.User, spec.CapAdd = "0", []string{"CHOWN", "FOWNER", "DAC_OVERRIDE"}
	man := FindManifest(p.Manifest, p.SnapshotID)
	var actual []ManifestFile
	res, err := s.runHelper(spec, func(h *helperRun, r *HelperResult) error {
		if r.ExitCode != 0 || !p.Verify || man == nil {
			return nil
		}
		rc, err := h.archive(s.ctx, "/restore")
		if err != nil {
			return s.dockerErr("read restored volume", err)
		}
		defer rc.Close()
		b := &Budget{Left: MaxManifestFiles * 2}
		actual, _, err = HashTar(rc, func(n string) string {
			if strings.HasPrefix(n, "/restore/") {
				return "/backup/" + t.Volume + strings.TrimPrefix(n, "/restore")
			}
			return ""
		}, b)
		if err != nil {
			return jerr(CodeRestoreFailed, "hash restored volume: %v", err)
		}
		return nil
	})
	if err != nil {
		if s.ctx.Err() != nil {
			return nil, jerr(CodeRestoreFailed, "restore aborted (%s)", timeLeft(s.ctx))
		}
		return nil, s.dockerErr("restore helper", err)
	}
	if res.ExitCode != 0 {
		return nil, s.resticResultErr("volume restore", res.ExitCode, res.Stdout, res.Stderr, CodeRestoreFailed)
	}
	po := ParseJSONLines(res.Stdout, 0)
	item := RestoredItem{Type: "volume", SnapshotID: p.SnapshotID, Mode: t.Mode}
	if po.Restore != nil {
		item.FilesRestored, item.BytesRestored = po.Restore.FilesRestored, po.Restore.BytesRestored
	}
	out.Restored = []RestoredItem{item}
	if p.Verify {
		if man != nil {
			n, mm := CompareFiles(man.Files, fileMap(actual), func(p string) string { return p }, nil)
			if mm == nil {
				mm = []Mismatch{}
			}
			out.Verify = &VerifyResult{OK: len(mm) == 0, Compared: n, Mismatches: mm, Method: "manifest"}
		} else {
			out.Verify = &VerifyResult{OK: true, Compared: int(item.FilesRestored), Mismatches: []Mismatch{}, Method: "restic"}
		}
	}
	return out, nil
}

// ScratchCreateBody builds the scratch DB container (no ports, isolated
// internal network, random password, CapDrop ALL + the minimum a DB image's
// entrypoint needs to chown its data dir and drop privileges).
func ScratchCreateBody(image, network, restoreID string, app string, env []string) map[string]any {
	mem := int64(1 << 30)
	return map[string]any{
		"Image":  image,
		"Env":    env,
		"Labels": map[string]string{containerops.LabelManaged: "true", containerops.LabelApp: app, LabelBackup: restoreID, LabelRole: "scratch"},
		"Tty":    false, "OpenStdin": false, "AttachStdin": false, "AttachStdout": false, "AttachStderr": false,
		"ExposedPorts": map[string]any{},
		"HostConfig": map[string]any{
			"PortBindings": map[string]any{}, "PublishAllPorts": false, "Privileged": false,
			"CapDrop": []string{"ALL"}, "CapAdd": []string{"CHOWN", "SETUID", "SETGID", "DAC_OVERRIDE", "FOWNER"},
			"SecurityOpt": containerops.SecurityOpt, "Memory": mem, "MemorySwap": mem, "NanoCpus": int64(2e9),
			"PidsLimit": int64(512), "RestartPolicy": map[string]any{"Name": "no"}, "NetworkMode": network,
			"IpcMode": "private", "ShmSize": int64(128 << 20),
			"LogConfig": map[string]any{"Type": "json-file", "Config": map[string]string{"max-size": "10m", "max-file": "1"}},
		},
	}
}

func (s *session) restoreDB(p RestoreParams) (*RestoreOutput, error) {
	t := p.Target
	out := &RestoreOutput{}
	if p.DryRun {
		var tables []string
		sha, size, _, err := s.fetchDump(p.SnapshotID, t.App, p.RestoreID, t.DumpFile(), tableScanner(&tables))
		if err != nil {
			return nil, err
		}
		if tables == nil {
			tables = []string{}
		}
		out.Plan = &DryRunInfo{DumpBytes: size, DumpSha256: sha, Tables: tables}
		return out, nil
	}
	var c dbConn
	var cleanup func() bool
	if t.Mode == "scratch" {
		var err error
		c, cleanup, err = s.startScratch(p)
		if cleanup != nil {
			defer cleanup()
		}
		if err != nil {
			return nil, err
		}
		out.Scratch = &ScratchInfo{Container: c.Host, Network: c.Network, Image: t.ScratchImage}
	} else {
		var err error
		if c, err = s.appConn(t.Target, p.RestoreID); err != nil {
			return nil, err
		}
		if err := s.ownedNetwork(t.App); err != nil {
			return nil, err
		}
	}
	sha, size, err := s.loadDump(p.SnapshotID, t.Target, c)
	if err != nil {
		return nil, err
	}
	item := RestoredItem{Type: t.Type, SnapshotID: p.SnapshotID, Mode: t.Mode, Database: t.Database, DumpBytes: size, DumpSha256: sha}
	out.Restored = []RestoredItem{item}
	if p.Verify {
		tables, cons, err := s.queryDB(c)
		if err != nil {
			return nil, err
		}
		out.Tables, out.Constraints = tables, cons
		if man := FindManifest(p.Manifest, p.SnapshotID); man != nil {
			n, mm := CompareTables(man.Tables, tables, man.Constraints, cons)
			if man.Sha256 != "" && man.Sha256 != sha {
				mm = append(mm, Mismatch{Path: "/" + t.DumpFile(), Reason: "dump", Expected: man.Sha256, Actual: sha})
			}
			if mm == nil {
				mm = []Mismatch{}
			}
			out.Verify = &VerifyResult{OK: len(mm) == 0, Compared: n, Mismatches: mm, Method: "manifest"}
		} else {
			out.Verify = &VerifyResult{OK: true, Compared: 0, Mismatches: []Mismatch{}, Method: "none"}
		}
	}
	if cleanup != nil {
		out.Scratch.Removed = cleanup()
	}
	return out, nil
}

// startScratch creates the isolated network + scratch DB container and waits
// until it accepts sessions. cleanup (idempotent) removes both and reports
// whether the container is gone; it is ALWAYS run (also on failure).
func (s *session) startScratch(p RestoreParams) (dbConn, func() bool, error) {
	t := p.Target
	e := s.m.o.Engine
	hex := randHex(4)
	network := "ppanel-restore-" + hex
	name := network + "-db"
	pw := randHex(24)
	s.addSecret(pw)
	c := dbConn{Type: t.Type, Host: name, Port: t.DefaultPort(), User: t.User, Password: pw, Database: t.Database,
		Network: network, App: t.App, Label: p.RestoreID}
	var env []string
	if t.Type == "mysql" {
		c.User = "root"
		env = []string{"MARIADB_ROOT_PASSWORD=" + pw, "MYSQL_ROOT_PASSWORD=" + pw, "MARIADB_DATABASE=" + t.Database, "MYSQL_DATABASE=" + t.Database}
	} else {
		env = []string{"POSTGRES_PASSWORD=" + pw, "POSTGRES_USER=" + t.User, "POSTGRES_DB=" + t.Database}
	}
	var netCreated, ctrCreated, done, removed bool
	cleanup := func() bool {
		if done {
			return removed
		}
		done = true
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		removed = true
		if ctrCreated {
			if err := e.RemoveScratchContainer(ctx, name); err != nil && !errors.Is(err, docker.ErrNotFound) {
				s.log.Error("scratch container removal failed", "name", name, "error", s.redact(err.Error()))
				removed = false
			}
		}
		if netCreated {
			if err := e.RemoveRestoreNetwork(ctx, network); err != nil && !errors.Is(err, docker.ErrNotFound) {
				s.log.Error("restore network removal failed", "name", network, "error", err.Error())
			}
		}
		return removed
	}
	labels := map[string]string{containerops.LabelManaged: "true", containerops.LabelApp: t.App, LabelBackup: p.RestoreID, LabelRole: "scratch"}
	if err := e.CreateInternalNetwork(s.ctx, network, labels); err != nil {
		return c, cleanup, s.dockerErr("create restore network", err)
	}
	netCreated = true
	if err := e.PullImage(s.ctx, t.ScratchImage, ""); err != nil {
		return c, cleanup, jerr(containerops.CodeImagePullFailed, "pull scratch image: %s", s.redact(err.Error()))
	}
	id, err := e.CreateContainer(s.ctx, name, ScratchCreateBody(t.ScratchImage, network, p.RestoreID, t.App, env))
	if err != nil {
		return c, cleanup, s.dockerErr("create scratch DB", err)
	}
	ctrCreated = true
	if err := e.StartContainer(s.ctx, id); err != nil {
		return c, cleanup, s.dockerErr("start scratch DB", err)
	}
	if err := s.waitReady(c); err != nil {
		return c, cleanup, err
	}
	return c, cleanup, nil
}

// ---------------- backup.verify ----------------

// VerifyOutput is the backup.verify output.
type VerifyOutput struct {
	SnapshotID    string     `json:"snapshotId"`
	RepoCheckOk   bool       `json:"repoCheckOk"`
	ReadDataPct   int        `json:"readDataSubsetPct"`
	FilesCompared int        `json:"filesCompared"`
	Mismatches    []Mismatch `json:"mismatches"`
	// Level: repository_checked (restic check only) | restore_verified (an
	// actual isolated restore was compared with the manifest).
	Level string `json:"level"`
}

// Verify implements backup.verify (read-only on the source; restores only
// into a temp dir / an ephemeral helper).
func (m *Manager) Verify(ctx context.Context, p VerifyParams) (any, error) {
	if err := m.CheckRestic(); err != nil {
		return nil, err
	}
	man := FindManifest(p.Manifest, p.SnapshotID)
	if man != nil && man.Type != "paths" {
		if _, err := m.CheckHelperImage(""); err != nil {
			return nil, err
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 6*time.Hour)
	defer cancel()
	release, err := m.lock(ctx, p.Repo.RepositoryID, nil)
	if err != nil {
		return nil, err
	}
	defer release()
	log := m.o.Log.With("job", "backup.verify", "snapshot", p.SnapshotID)
	s, err := m.newSession(ctx, p.Repo, log)
	if err != nil {
		return nil, err
	}
	out := VerifyOutput{SnapshotID: p.SnapshotID, ReadDataPct: p.ReadDataSubsetPct, Mismatches: []Mismatch{}, Level: "none"}
	args := []string{"-r", p.Repo.ResticURL(), "check", "--json"}
	if p.ReadDataSubsetPct > 0 {
		args = append(args, "--read-data-subset="+itoa(int64(p.ReadDataSubsetPct))+"%")
	}
	res, err := s.restic(args, 8<<20)
	if err != nil {
		return nil, s.redactErr(jerr(CodeVerifyFailed, "restic check: %v", err))
	}
	if res.ExitCode != 0 {
		text := failureText(res.Stdout, res.Stderr)
		code := ClassifyFailure(res.ExitCode, text, CodeVerifyFailed)
		e := jerr(code, "restic check failed (exit %d): %s", res.ExitCode, text)
		e.Details = out
		return nil, s.redactErr(e)
	}
	out.RepoCheckOk, out.Level = true, "repository_checked"
	if man != nil {
		n, mm, err := s.verifyRestore(p, man)
		if err != nil {
			return nil, s.redactErr(err)
		}
		out.FilesCompared, out.Mismatches = n, mm
		if len(mm) > 0 {
			e := jerr(CodeVerifyFailed, "restore test of snapshot %s: %d mismatches", p.SnapshotID, len(mm))
			e.Details = out
			return nil, s.redactErr(e)
		}
		out.Level = "restore_verified"
	}
	return s.redactOut(out)
}

func (s *session) verifyRestore(p VerifyParams, man *ManifestEntry) (int, []Mismatch, error) {
	label := "verify-" + randHex(4)
	switch man.Type {
	case "paths":
		dir := filepath.Join(s.m.o.WorkDir, "verify", randHex(8))
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return 0, nil, jerr(CodeVerifyFailed, "create verify dir: %v", err)
		}
		defer os.RemoveAll(dir)
		res, err := s.restic(restoreArgs(p.Repo, p.SnapshotID, false, dir, nil, false, false, false), 8<<20)
		if err != nil {
			return 0, nil, jerr(CodeVerifyFailed, "restic restore (verify): %v", err)
		}
		if res.ExitCode != 0 {
			return 0, nil, s.resticResultErr("verify restore", res.ExitCode, res.Stdout, res.Stderr, CodeVerifyFailed)
		}
		v := verifyFiles(man.Files, dir, nil)
		return v.Compared, v.Mismatches, nil
	case "volume":
		if err := s.prepareHelper(""); err != nil {
			return 0, nil, err
		}
		spec := s.helper("verify", man.App, label, restoreArgs(p.Repo, p.SnapshotID+":/backup/"+man.Volume, true, "/restore", nil, false, false, false), nil)
		spec.Writable = true
		spec.User, spec.CapAdd = "0", []string{"CHOWN", "FOWNER", "DAC_OVERRIDE"}
		var actual []ManifestFile
		res, err := s.runHelper(spec, func(h *helperRun, r *HelperResult) error {
			if r.ExitCode != 0 {
				return nil
			}
			rc, err := h.archive(s.ctx, "/restore")
			if err != nil {
				return s.dockerErr("read verify restore", err)
			}
			defer rc.Close()
			actual, _, err = HashTar(rc, func(n string) string {
				if strings.HasPrefix(n, "/restore/") {
					return "/backup/" + man.Volume + strings.TrimPrefix(n, "/restore")
				}
				return ""
			}, &Budget{Left: MaxManifestFiles * 2})
			return err
		})
		if err != nil {
			return 0, nil, s.dockerErr("verify helper", err)
		}
		if res.ExitCode != 0 {
			return 0, nil, s.resticResultErr("verify restore", res.ExitCode, res.Stdout, res.Stderr, CodeVerifyFailed)
		}
		n, mm := CompareFiles(man.Files, fileMap(actual), func(p string) string { return p }, nil)
		if mm == nil {
			mm = []Mismatch{}
		}
		return n, mm, nil
	default:
		if err := s.prepareHelper(""); err != nil {
			return 0, nil, err
		}
		sha, size, _, err := s.fetchDump(p.SnapshotID, man.App, label, man.Database+".sql", nil)
		if err != nil {
			return 0, nil, err
		}
		var mm []Mismatch
		if sha != man.Sha256 {
			mm = append(mm, Mismatch{Path: "/" + man.Database + ".sql", Reason: "sha256", Expected: man.Sha256, Actual: sha})
		}
		if size != man.Bytes {
			mm = append(mm, Mismatch{Path: "/" + man.Database + ".sql", Reason: "size", Expected: itoa(man.Bytes), Actual: itoa(size)})
		}
		if mm == nil {
			mm = []Mismatch{}
		}
		return 1, mm, nil
	}
}

var _ = jobs.HandlerFailed
