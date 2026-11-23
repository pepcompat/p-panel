package backupops

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ppanel/ppanel/apps/agent/internal/containerops"
	"github.com/ppanel/ppanel/apps/agent/internal/docker"
	"github.com/ppanel/ppanel/apps/agent/internal/execx"
	"github.com/ppanel/ppanel/apps/agent/internal/transport"
)

// Real-lab P6 tests. Opt-in, driven by scripts/lab/agent_backup_lab.sh, run INSIDE the lab nodes against
// lab-backup (rest-server --private-repos --append-only) with the node's own (append-only) credential:
//
//	PPANEL_LAB_BACKUP=1 + .lab/backup/servers/<node>.env (PPANEL_LAB_BK_USER/_REST_PASSWORD/_REPO_PASSWORD)
//	node-a: TestLabP6Files   (P6-T01 files, append-only proof, P6-T04 kill mid-run)
//	node-b: TestLabP6Docker  (P6-T02 postgres dump → scratch restore, volume backup/restore; needs
//	        PPANEL_LAB_BACKUP_HELPER_IMAGE and PPANEL_LAB_BACKUP_SCRATCH_PG)

func labEnv(t *testing.T) (user, restPW, repoPW string) {
	t.Helper()
	if os.Getenv("PPANEL_LAB_BACKUP") != "1" {
		t.Skip("set PPANEL_LAB_BACKUP=1 (inside a lab node, see scripts/lab/agent_backup_lab.sh)")
	}
	user, restPW, repoPW = os.Getenv("PPANEL_LAB_BK_USER"), os.Getenv("PPANEL_LAB_BK_REST_PASSWORD"), os.Getenv("PPANEL_LAB_BK_REPO_PASSWORD")
	if user == "" || restPW == "" || repoPW == "" {
		t.Fatal("PPANEL_LAB_BK_USER/_REST_PASSWORD/_REPO_PASSWORD required")
	}
	return
}

func uuid4() string {
	b := make([]byte, 16)
	rand.Read(b)
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b)
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

func labManager(t *testing.T, user, restPW, repoPW string, env map[string]string, eng *docker.Engine, helper string) *Manager {
	t.Helper()
	bin := "/usr/local/bin/restic"
	ver, err := DetectRestic(context.Background(), execx.System{}, bin)
	if err != nil {
		t.Fatalf("host restic: %v", err)
	}
	state := "/var/lib/ppanel-p6-labtest"
	os.MkdirAll(state, 0o700)
	host, _ := os.Hostname()
	return New(Options{Engine: eng, Exec: execx.System{}, ResticBin: bin, ResticVersion: ver, HelperImage: helper, StateDir: state,
		WorkDir: filepath.Join(state, "backup"), Hostname: host, ScratchReadyTimeout: 3 * time.Minute, ReadyInterval: time.Second,
		Log: slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})),
		Secrets: func(context.Context) (*transport.JobSecrets, error) {
			return &transport.JobSecrets{Env: env, Restic: &transport.ResticSecrets{RepoPassword: repoPW, RestUser: user, RestPassword: restPW}}, nil
		}})
}

func labRepo(user string) map[string]any {
	return map[string]any{"url": "http://lab-backup:8000/" + user + "/", "repositoryId": "6f1c0de0-0000-4000-8000-0000000000" + map[bool]string{true: "0a", false: "0b"}[user == "node-a"]}
}

func dump(t *testing.T, label string, v any) []byte {
	t.Helper()
	b, _ := json.MarshalIndent(v, "", "  ")
	s := string(b)
	if len(s) > 3000 {
		s = s[:3000] + "\n…"
	}
	t.Logf("%s:\n%s", label, s)
	b, _ = json.Marshal(v)
	return b
}

func sha(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

func treeSums(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		switch {
		case d.Type()&os.ModeSymlink != 0:
			l, _ := os.Readlink(p)
			out[rel] = "link:" + l
		case d.Type().IsRegular():
			b, _ := os.ReadFile(p)
			out[rel] = sha(b)
		}
		return nil
	})
	return out
}

func resticAs(t *testing.T, user, restPW, repoPW string, args ...string) execx.Result {
	t.Helper()
	res, err := execx.System{}.RunCmd(context.Background(), execx.Cmd{Binary: "/usr/local/bin/restic",
		Args: append([]string{"--no-cache", "-r", "rest:http://lab-backup:8000/" + user + "/"}, args...),
		Env:  []string{"RESTIC_PASSWORD=" + repoPW, "RESTIC_REST_USERNAME=" + user, "RESTIC_REST_PASSWORD=" + restPW}, Timeout: 2 * time.Minute})
	if err != nil {
		t.Fatalf("restic %v: %v", args, err)
	}
	return res
}

func TestLabP6Files(t *testing.T) {
	user, restPW, repoPW := labEnv(t)
	m := labManager(t, user, restPW, repoPW, map[string]string{}, nil, "")
	ctx := context.Background()

	// ---- P6-T01: back up a test dir with known checksums → delete → restore to staging → identical ----
	src := "/srv/p6-t01"
	os.RemoveAll(src)
	os.MkdirAll(filepath.Join(src, "nested/deeper"), 0o755)
	for i := 0; i < 25; i++ {
		b := make([]byte, 1000+i*997)
		rand.Read(b)
		os.WriteFile(filepath.Join(src, fmt.Sprintf("nested/f%02d.bin", i)), b, 0o644)
	}
	os.WriteFile(filepath.Join(src, "nested/deeper/readme.txt"), []byte("pPanel P6-T01\n"), 0o600)
	os.Symlink("nested/deeper/readme.txt", filepath.Join(src, "link-to-readme"))
	before := treeSums(t, src)
	runID := uuid4()
	bp, err := DecodeBackup(mustJSON(map[string]any{"runId": runID, "policyId": uuid4(), "repo": labRepo(user),
		"targets": []any{map[string]any{"type": "paths", "paths": []string{src}}}, "tags": []string{"lab=p6-t01"}}))
	if err != nil {
		t.Fatal(err)
	}
	out, err := m.Backup(ctx, bp)
	if err != nil {
		dump(t, "backup error", err)
		t.Fatal(err)
	}
	var bo BackupOutput
	json.Unmarshal(dump(t, "P6-T01 backup.run output", out), &bo)
	if len(bo.Snapshots) != 1 || bo.Manifest[0].FileCount != 26 {
		t.Fatalf("snapshot/manifest: %+v", bo)
	}
	snap := bo.Snapshots[0].SnapshotID
	if err := os.RemoveAll(src); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(src); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("source not deleted")
	}
	restoreID := uuid4()
	rp, err := DecodeRestore(mustJSON(map[string]any{"restoreId": restoreID, "repo": labRepo(user), "snapshotId": bo.Snapshots[0].ShortID,
		"target": map[string]any{"type": "paths", "mode": "staging"}, "manifest": bo.Manifest}))
	if err != nil {
		t.Fatal(err)
	}
	// dry run first: nothing written
	dry := rp
	dry.DryRun = true
	dout, err := m.Restore(ctx, dry)
	if err != nil {
		t.Fatal(err)
	}
	dump(t, "P6-T01 restore dryRun output (truncated)", dout)
	if _, err := os.Stat(m.StagingDir(restoreID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("dry run created the staging dir")
	}
	rout, err := m.Restore(ctx, rp)
	if err != nil {
		dump(t, "restore error", err)
		t.Fatal(err)
	}
	var ro RestoreOutput
	json.Unmarshal(dump(t, "P6-T01 restore.run output", rout), &ro)
	st, err := os.Stat(ro.StagingPath)
	if err != nil || st.Mode().Perm() != 0o700 {
		t.Fatalf("staging perms: %v %v", st.Mode(), err)
	}
	after := treeSums(t, filepath.Join(ro.StagingPath, src))
	if len(after) != len(before) {
		t.Fatalf("restored %d entries, want %d", len(after), len(before))
	}
	for k, v := range before {
		if after[k] != v {
			t.Fatalf("P6-T01 checksum mismatch %s: %s != %s", k, after[k], v)
		}
	}
	if !ro.Verify.OK || ro.Verify.Compared != 26 {
		t.Fatalf("verify: %+v", ro.Verify)
	}
	t.Logf("P6-T01 PASS: %d entries (26 files + 1 symlink) identical after delete + staging restore (%s)", len(before), ro.StagingPath)

	// backup.verify with the manifest → restore_verified
	vp, err := DecodeVerify(mustJSON(map[string]any{"repo": labRepo(user), "snapshotId": snap, "readDataSubsetPct": 100, "manifest": bo.Manifest}))
	if err != nil {
		t.Fatal(err)
	}
	vout, err := m.Verify(ctx, vp)
	if err != nil {
		dump(t, "verify error", err)
		t.Fatal(err)
	}
	if b := dump(t, "backup.verify output", vout); !strings.Contains(string(b), `"level":"restore_verified"`) {
		t.Fatal("not restore_verified")
	}
	// a tampered manifest is detected
	bad := append([]ManifestEntry(nil), bo.Manifest...)
	bad[0].Files = append([]ManifestFile(nil), bad[0].Files...)
	bad[0].Files[0].Sha256 = strings.Repeat("0", 64)
	vp.Manifest, vp.ReadDataSubsetPct = bad, 0
	if _, err := m.Verify(ctx, vp); err == nil || !strings.Contains(err.Error(), CodeVerifyFailed) {
		t.Fatalf("tampered manifest not detected: %v", err)
	}

	// ---- append-only proof with the AGENT credential ----
	res := resticAs(t, user, restPW, repoPW, "forget", snap)
	t.Logf("append-only: agent `restic forget %s` exit=%d stderr=%q", snap[:8], res.ExitCode, truncate(strings.TrimSpace(string(res.Stderr)), 300))
	if res.ExitCode == 0 && !strings.Contains(string(res.Stderr), "403") {
		t.Fatal("forget with the agent credential must fail on the append-only rest-server")
	}
	ls := resticAs(t, user, restPW, repoPW, "snapshots", "--json", snap[:8])
	if ls.ExitCode != 0 || !strings.Contains(string(ls.Stdout), snap) {
		t.Fatalf("snapshot gone after forget attempt: %s", ls.Stdout)
	}
	t.Logf("append-only PASS: forget refused, snapshot %s still present; backup with the same credential succeeded", snap[:8])

	// ---- P6-T04: kill a backup mid-run → BACKUP_FAILED and no snapshot for that run ----
	big := "/srv/p6-t04"
	os.RemoveAll(big)
	os.MkdirAll(big, 0o755)
	f, _ := os.Create(filepath.Join(big, "random.bin"))
	io.CopyN(f, rand.Reader, 48<<20)
	f.Close()
	killRun := uuid4()
	kp, _ := DecodeBackup(mustJSON(map[string]any{"runId": killRun, "policyId": uuid4(), "repo": labRepo(user),
		"targets": []any{map[string]any{"type": "paths", "paths": []string{big}}}, "limits": map[string]any{"uploadKiBps": 256}}))
	kctx, cancel := context.WithCancel(ctx)
	time.AfterFunc(5*time.Second, cancel)
	start := time.Now()
	kout, kerr := m.Backup(kctx, kp)
	el := time.Since(start)
	dump(t, "P6-T04 backup.run result (cancelled after 5s)", map[string]any{"output": kout, "error": kerr, "elapsed": el.String()})
	if kout != nil || kerr == nil || !(strings.Contains(kerr.Error(), CodeBackupFailed) || strings.Contains(kerr.Error(), CodeBackupPartial)) {
		t.Fatalf("killed run: %v %v", kout, kerr)
	}
	if el > 40*time.Second {
		t.Fatalf("cancel took %s", el)
	}
	sp, _ := DecodeSnapshots(mustJSON(map[string]any{"repo": labRepo(user), "tag": "run=" + killRun}))
	sout, err := m.Snapshots(ctx, sp)
	if err != nil {
		t.Fatal(err)
	}
	if b := dump(t, "backup.snapshots tag=run=<killed run>", sout); !strings.Contains(string(b), `"snapshots":[]`) {
		t.Fatal("a snapshot exists for the killed run")
	}
	// restic removed its lock on SIGINT: the next runs are not REPO_LOCKED (two snapshots of the same
	// host+paths group, so the maintenance prune in agent_backup_lab.sh has something to remove)
	os.RemoveAll(big)
	for i := 0; i < 2; i++ {
		nb, _ := DecodeBackup(mustJSON(map[string]any{"runId": uuid4(), "policyId": uuid4(), "repo": labRepo(user),
			"targets": []any{map[string]any{"type": "paths", "paths": []string{"/etc/nginx"}}}}))
		if _, err := m.Backup(ctx, nb); err != nil {
			t.Fatalf("backup after the killed run: %v", err)
		}
	}
	t.Logf("P6-T04 PASS: cancelled run → %v after %s; no snapshot tagged run=%s; next run not locked", kerr.(interface{ Error() string }).Error()[:14], el.Round(time.Millisecond), killRun)
	all, _ := DecodeSnapshots(mustJSON(map[string]any{"repo": labRepo(user)}))
	aout, _ := m.Snapshots(ctx, all)
	dump(t, "backup.snapshots (all)", aout)
}

// ---------------- node-b: postgres + volume via the helper on lab-dind ----------------

func TestLabP6Docker(t *testing.T) {
	user, restPW, repoPW := labEnv(t)
	helper, scratch := os.Getenv("PPANEL_LAB_BACKUP_HELPER_IMAGE"), os.Getenv("PPANEL_LAB_BACKUP_SCRATCH_PG")
	if !containerops.ImageDigestRefRe.MatchString(helper) || !containerops.ImageDigestRefRe.MatchString(scratch) {
		t.Fatal("PPANEL_LAB_BACKUP_HELPER_IMAGE / PPANEL_LAB_BACKUP_SCRATCH_PG must be digest refs")
	}
	eng := docker.NewEngine("/var/run/docker.sock")
	ctx := context.Background()
	if err := eng.Ping(ctx); err != nil {
		t.Fatal(err)
	}
	const app = "p6lab"
	dbPW := "p6-" + randHex(16)
	m := labManager(t, user, restPW, repoPW, map[string]string{"DB_PASSWORD": dbPW}, eng, helper)
	s, err := m.newSession(ctx, RepoRef{URL: "http://lab-backup:8000/" + user + "/", RepositoryID: uuid4()}, m.o.Log)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.prepareHelper(""); err != nil {
		t.Fatal(err)
	}
	t.Logf("helper ExtraHosts (resolved by the agent): %v", s.extraHosts)

	// ---- app fixture: managed network + postgres "db" service with ownership labels ----
	labels := map[string]string{containerops.LabelManaged: "true", containerops.LabelApp: app}
	if _, err := eng.InspectNetwork(ctx, "ppanel-"+app); err != nil {
		if err := eng.CreateNetwork(ctx, "ppanel-"+app, labels); err != nil {
			t.Fatal(err)
		}
	}
	if err := eng.PullImage(ctx, scratch, ""); err != nil {
		t.Fatal(err)
	}
	dbName := "ppanel-" + app + "-db-" + randHex(4)
	body := map[string]any{"Image": scratch, "Env": []string{"POSTGRES_PASSWORD=" + dbPW, "POSTGRES_USER=shop", "POSTGRES_DB=shop"},
		"Labels": map[string]string{containerops.LabelManaged: "true", containerops.LabelApp: app, containerops.LabelService: "db"},
		"HostConfig": map[string]any{"NetworkMode": "ppanel-" + app, "Tmpfs": map[string]string{"/var/lib/postgresql/data": "rw,size=512m"},
			"CapDrop": []string{"ALL"}, "CapAdd": []string{"CHOWN", "SETUID", "SETGID", "DAC_OVERRIDE", "FOWNER"},
			"SecurityOpt": []string{"no-new-privileges:true"}, "Memory": int64(512 << 20)},
		"NetworkingConfig": map[string]any{"EndpointsConfig": map[string]any{"ppanel-" + app: map[string]any{"Aliases": []string{"db"}}}}}
	id, err := eng.CreateContainer(ctx, dbName, body)
	if err != nil {
		t.Fatal(err)
	}
	defer eng.RemoveContainer(context.Background(), id, true)
	if err := eng.StartContainer(ctx, id); err != nil {
		t.Fatal(err)
	}
	appConn := dbConn{Type: "postgres", Host: "db", Port: 5432, User: "shop", Password: dbPW, Database: "shop", Network: "ppanel-" + app, App: app, Label: "p6-seed"}
	if err := s.waitReady(appConn); err != nil {
		t.Fatal(err)
	}
	seed := `create table customers (id serial constraint customers_pkey primary key, email text not null constraint customers_email_key unique,
  credit numeric(10,2) not null default 0 constraint customers_credit_check check (credit >= 0));
create table orders (id serial constraint orders_pkey primary key,
  customer_id int not null constraint orders_customer_fk references customers(id) on delete cascade,
  total numeric(10,2) not null constraint orders_total_check check (total > 0), placed_at timestamptz not null default now());
create table order_items (order_id int not null constraint order_items_order_fk references orders(id),
  line int not null, sku text not null, qty int not null constraint order_items_qty_check check (qty between 1 and 99),
  constraint order_items_pkey primary key (order_id, line));
insert into customers (email, credit) select 'c' || g || '@lab.test', g * 1.5 from generate_series(1, 57) g;
insert into orders (customer_id, total) select 1 + (g % 57), 10 + g from generate_series(1, 211) g;
insert into order_items select o.id, l, 'SKU-' || o.id || '-' || l, 1 + (o.id + l) % 9 from orders o, generate_series(1, 3) l;
create index orders_customer_idx on orders (customer_id);`
	entry, args := clientArgs(appConn, seed, "")
	res, err := s.runHelper(s.clientSpec("query", appConn, entry, args), nil)
	if err != nil || res.ExitCode != 0 {
		t.Fatalf("seed: %v %s", err, res.Stderr)
	}
	srcTables, srcCons, err := s.queryDB(appConn)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("source tables %v constraints %v", srcTables, srcCons)

	// ---- managed volume fixture (filled through a helper mount + the archive API) ----
	vol := containerops.VolumeName(app, "files")
	if _, err := eng.CreateVolume(ctx, vol, labels); err != nil {
		t.Fatal(err)
	}
	fill := s.helper("restore", app, "p6-fill", []string{"version"}, nil)
	fill.Mounts = []Mount{{Volume: vol, Target: "/restore"}}
	fill.User, fill.Writable = "0", true
	h, err := createHelper(ctx, eng, fill, s.log)
	if err != nil {
		t.Fatal(err)
	}
	payload := map[string][]byte{"index.html": []byte("<h1>p6</h1>\n"), "uploads/a.bin": make([]byte, 70000), "uploads/b.txt": []byte(randHex(64))}
	rand.Read(payload["uploads/a.bin"])
	pr, pw := io.Pipe()
	go func() { pw.CloseWithError(writeTar(pw, payload)) }()
	if err := eng.PutArchive(ctx, h.name, "/restore", pr); err != nil {
		t.Fatal(err)
	}
	h.remove()

	// ---- backup.run: postgres dump + volume ----
	runID := uuid4()
	bp, err := DecodeBackup(mustJSON(map[string]any{"runId": runID, "policyId": uuid4(), "repo": labRepo(user), "helperImage": helper,
		"targets": []any{
			map[string]any{"type": "postgres", "app": app, "service": "db", "database": "shop", "user": "shop", "passwordSecretKey": "DB_PASSWORD"},
			map[string]any{"type": "volume", "app": app, "volume": "files"},
		}}))
	if err != nil {
		t.Fatal(err)
	}
	out, err := m.Backup(ctx, bp)
	if err != nil {
		dump(t, "backup error", err)
		t.Fatal(err)
	}
	ob := dump(t, "P6-T02 backup.run output", out)
	if strings.Contains(string(ob), dbPW) || strings.Contains(string(ob), repoPW) || strings.Contains(string(ob), restPW) {
		t.Fatal("secret in backup output")
	}
	var bo BackupOutput
	json.Unmarshal(ob, &bo)
	if len(bo.Snapshots) != 2 || bo.Manifest[0].Sha256 == "" || len(bo.Manifest[0].Tables) != 3 || bo.Manifest[1].FileCount != 3 {
		t.Fatalf("backup output: %+v", bo)
	}
	if !slices.Equal(bo.Manifest[0].Constraints, srcCons) {
		t.Fatalf("manifest constraints %v != source %v", bo.Manifest[0].Constraints, srcCons)
	}

	// ---- P6-T02: scratch restore → row counts + constraint names identical, scratch removed ----
	restoreID := uuid4()
	rp, err := DecodeRestore(mustJSON(map[string]any{"restoreId": restoreID, "repo": labRepo(user), "snapshotId": bo.Snapshots[0].SnapshotID,
		"helperImage": helper, "manifest": bo.Manifest,
		"target": map[string]any{"type": "postgres", "app": app, "service": "db", "database": "shop", "user": "shop",
			"passwordSecretKey": "DB_PASSWORD", "mode": "scratch", "scratchImage": scratch}}))
	if err != nil {
		t.Fatal(err)
	}
	dry := rp
	dry.DryRun = true
	dout, err := m.Restore(ctx, dry)
	if err != nil {
		t.Fatal(err)
	}
	dump(t, "P6-T02 restore dryRun output", dout)
	rout, err := m.Restore(ctx, rp)
	if err != nil {
		dump(t, "scratch restore error", err)
		t.Fatal(err)
	}
	var ro RestoreOutput
	json.Unmarshal(dump(t, "P6-T02 restore.run (scratch) output", rout), &ro)
	if !ro.Verify.OK || !ro.Scratch.Removed {
		t.Fatalf("scratch restore: %+v", ro)
	}
	if !slices.Equal(ro.Constraints, srcCons) || len(ro.Tables) != len(srcTables) {
		t.Fatalf("constraints/tables differ: %v vs %v", ro.Constraints, srcCons)
	}
	for i := range srcTables {
		if ro.Tables[i] != srcTables[i] {
			t.Fatalf("row counts differ: %v vs %v", ro.Tables, srcTables)
		}
	}
	if _, err := eng.InspectContainer(ctx, ro.Scratch.Container); !errors.Is(err, docker.ErrNotFound) {
		t.Fatalf("scratch container still present: %v", err)
	}
	if _, err := eng.InspectNetwork(ctx, ro.Scratch.Network); !errors.Is(err, docker.ErrNotFound) {
		t.Fatalf("restore network still present: %v", err)
	}
	t.Logf("P6-T02 PASS: tables %v, %d constraint names identical; scratch %s + network %s removed", ro.Tables, len(ro.Constraints), ro.Scratch.Container, ro.Scratch.Network)

	// ---- backup.verify of the DB snapshot (dump re-hash) and the volume snapshot (isolated restore + re-hash) ----
	for i, snap := range bo.Snapshots {
		vp, _ := DecodeVerify(mustJSON(map[string]any{"repo": labRepo(user), "snapshotId": snap.SnapshotID, "readDataSubsetPct": 25, "manifest": bo.Manifest}))
		vout, err := m.Verify(ctx, vp)
		if err != nil {
			dump(t, "verify error", err)
			t.Fatal(err)
		}
		if b := dump(t, fmt.Sprintf("backup.verify target %d", i), vout); !strings.Contains(string(b), `"level":"restore_verified"`) {
			t.Fatal("not restore_verified")
		}
	}

	// ---- volume staging restore into a NEW volume, verified against the manifest ----
	vr, _ := DecodeRestore(mustJSON(map[string]any{"restoreId": uuid4(), "repo": labRepo(user), "snapshotId": bo.Snapshots[1].ShortID,
		"manifest": bo.Manifest, "target": map[string]any{"type": "volume", "app": app, "volume": "files", "mode": "staging"}}))
	vout, err := m.Restore(ctx, vr)
	if err != nil {
		dump(t, "volume restore error", err)
		t.Fatal(err)
	}
	var vo RestoreOutput
	json.Unmarshal(dump(t, "volume staging restore output", vout), &vo)
	if !vo.Verify.OK || vo.Verify.Compared != 3 || !strings.HasPrefix(vo.Volume, "ppanel-"+app+"-restore-") {
		t.Fatalf("volume restore: %+v", vo)
	}
	// no helper / scratch containers left behind
	left, _ := eng.ListContainers(ctx, []string{LabelBackup})
	if len(left) != 0 {
		t.Fatalf("leftover ppanel.backup containers: %+v", left)
	}
	t.Logf("volume PASS: %d files restored to %s and verified; no ppanel.backup containers left", vo.Verify.Compared, vo.Volume)
}
