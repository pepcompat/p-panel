package backupops

import (
	"encoding/json"
	"strings"
	"testing"
)

const fzRepo = `{"url":"https://repo.example:8000/srv1/","repositoryId":"0190f4c2-0000-7000-8000-000000000001"}`
const fzUUID = "0190f4c2-0000-7000-8000-0000000000e1"

func assertHostPath(t *testing.T, p string) {
	t.Helper()
	if CheckHostPath(p) != nil || !strings.HasPrefix(p, "/") || strings.HasPrefix(p, "-") || strings.Contains(p, "//") ||
		strings.ContainsAny(p, "\x00\n\r \\") {
		t.Fatalf("host path accepted: %q", p)
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == ".." || seg == "." {
			t.Fatalf("non-canonical host path accepted: %q", p)
		}
	}
	for _, d := range []string{"/proc", "/sys", "/dev"} {
		if p == d || strings.HasPrefix(p, d+"/") {
			t.Fatalf("pseudo-fs path accepted: %q", p)
		}
	}
}

func assertTarget(t *testing.T, tg Target) {
	t.Helper()
	switch tg.Type {
	case "paths":
		for _, p := range tg.Paths {
			assertHostPath(t, p)
		}
		for _, e := range tg.Excludes {
			if strings.HasPrefix(e, "-") {
				t.Fatalf("exclude option injection %q", e)
			}
		}
	case "volume":
		if !strings.HasPrefix(tg.VolumeName(), "ppanel-"+tg.App+"-") || strings.ContainsAny(tg.Volume, "/.") {
			t.Fatalf("volume %q", tg.VolumeName())
		}
	case "postgres", "mysql":
		for _, v := range []string{tg.Database, tg.User, tg.Service} {
			if v == "" || strings.HasPrefix(v, "-") || strings.ContainsAny(v, " \x00/;'\"") {
				t.Fatalf("db field %q", v)
			}
		}
		if tg.DefaultPort() < 1 || tg.DefaultPort() > 65535 {
			t.Fatalf("port %d", tg.DefaultPort())
		}
	default:
		t.Fatalf("type %q", tg.Type)
	}
}

func assertManifest(t *testing.T, ms []ManifestEntry) {
	t.Helper()
	for _, m := range ms {
		for _, f := range m.Files {
			assertHostPath(t, f.Path)
		}
	}
}

func FuzzCheckHostPath(f *testing.F) {
	for _, s := range []string{"/srv/www", "/backup/../etc/shadow", "/proc/self/environ", "/", "/a/./b", "//etc", "/etc/", "-x", "/a b"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, p string) {
		if CheckHostPath(p) == nil {
			assertHostPath(t, p)
		}
	})
}

// FuzzDecodeBackupParams drives backup.run / backup.snapshots / backup.verify /
// restore.run decoders. Accepted params: canonical host paths only, no '-'
// option values, owned volume names, digest-pinned images, bounded lists,
// manifest paths canonical.
func FuzzDecodeBackupParams(f *testing.F) {
	seeds := []string{
		`{"runId":"` + fzUUID + `","policyId":"` + fzUUID + `","repo":` + fzRepo + `,"targets":[{"type":"paths","paths":["/srv/www"],"excludes":["*.tmp"]},{"type":"volume","app":"shop","volume":"data"},{"type":"postgres","app":"shop","service":"db","database":"shop","user":"shop","passwordSecretKey":"DB_PASSWORD","port":5432}],"tags":["daily"],"limits":{"timeoutSec":600}}`,
		`{"repo":` + fzRepo + `,"tag":"daily"}`,
		`{"repo":` + fzRepo + `,"snapshotId":"0123abcd","readDataSubsetPct":5,"manifest":[{"target":0,"type":"paths","snapshotId":"0123abcd","files":[{"path":"/backup/../etc/shadow","size":1,"sha256":"` + strings.Repeat("a", 64) + `"}],"fileCount":1,"truncated":false}]}`,
		`{"restoreId":"` + fzUUID + `","repo":` + fzRepo + `,"snapshotId":"0123abcd","target":{"type":"paths","mode":"in_place","include":["/srv/www"]},"verify":true}`,
		`{"restoreId":"` + fzUUID + `","repo":` + fzRepo + `,"snapshotId":"0123abcd","target":{"type":"postgres","app":"shop","service":"db","database":"--file=/etc/passwd","user":"u","passwordSecretKey":"PW","mode":"scratch"}}`,
		`{"runId":"` + fzUUID + `","policyId":"` + fzUUID + `","repo":{"url":"rest:https://u:p@repo/x","repositoryId":"` + fzUUID + `"},"targets":[{"type":"paths","paths":["/proc/1/environ"]}]}`,
	}
	for i, s := range seeds {
		f.Add(uint8(i), []byte(s))
	}
	f.Fuzz(func(t *testing.T, which uint8, raw []byte) {
		check := func(r RepoRef) {
			if strings.Contains(r.URL, "@") || strings.HasPrefix(r.URL, "-") || strings.Contains(r.URL, "..") ||
				!(strings.HasPrefix(r.ResticURL(), "rest:http://") || strings.HasPrefix(r.ResticURL(), "rest:https://")) {
				t.Fatalf("repo url %q", r.URL)
			}
		}
		switch which % 4 {
		case 0:
			p, err := DecodeBackup(raw)
			if err != nil {
				return
			}
			check(p.Repo)
			if len(p.Targets) < 1 || len(p.Targets) > 20 || len(p.Tags) > 20 {
				t.Fatalf("bounds %d %d", len(p.Targets), len(p.Tags))
			}
			for _, tg := range p.Targets {
				assertTarget(t, tg)
			}
			for _, tag := range p.Tags {
				if strings.HasPrefix(tag, "-") {
					t.Fatalf("tag %q", tag)
				}
			}
			if p.HelperImage != "" && !strings.Contains(p.HelperImage, "@sha256:") {
				t.Fatalf("helper image %q", p.HelperImage)
			}
		case 1:
			if p, err := DecodeSnapshots(raw); err == nil {
				check(p.Repo)
				if strings.HasPrefix(p.Tag, "-") {
					t.Fatalf("tag %q", p.Tag)
				}
			}
		case 2:
			if p, err := DecodeVerify(raw); err == nil {
				check(p.Repo)
				if !snapshotRe.MatchString(p.SnapshotID) || p.ReadDataSubsetPct < 0 || p.ReadDataSubsetPct > 100 {
					t.Fatalf("%+v", p)
				}
				assertManifest(t, p.Manifest)
			}
		case 3:
			p, err := DecodeRestore(raw)
			if err != nil {
				return
			}
			check(p.Repo)
			assertTarget(t, p.Target.Target)
			for _, inc := range p.Target.Include {
				assertHostPath(t, inc)
			}
			if !restoreModes[p.Target.Type][p.Target.Mode] {
				t.Fatalf("mode %q for %q", p.Target.Mode, p.Target.Type)
			}
			if p.Target.Type == "paths" && p.Target.Mode == "in_place" && len(p.Target.Include) == 0 {
				t.Fatal("in_place paths restore of everything accepted")
			}
			if p.Target.ScratchImage != "" && !strings.Contains(p.Target.ScratchImage, "@sha256:") {
				t.Fatalf("scratch image %q", p.Target.ScratchImage)
			}
			if !strings.HasPrefix(StagingDirName(p.RestoreID), "") || strings.ContainsAny(p.RestoreID, "/.") {
				t.Fatalf("restoreId %q", p.RestoreID)
			}
			assertManifest(t, p.Manifest)
			// argv built from it never carries an injected option
			a := restoreArgs(p.Repo, p.SnapshotID, false, "/tmp/s", p.Target.Include, p.DryRun, p.Verify, false)
			for i, x := range a {
				if strings.HasPrefix(x, "-") && i > 0 && (a[i-1] == "--include" || a[i-1] == "--target" || a[i-1] == "-r") {
					t.Fatalf("option-looking value %q after %q", x, a[i-1])
				}
			}
		}
		_ = json.Valid
	})
}

// StagingDirName is the last element of a staging dir (test helper).
func StagingDirName(id string) string { return id }
