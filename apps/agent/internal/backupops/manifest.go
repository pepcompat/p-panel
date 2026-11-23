package backupops

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

// Budget is the remaining number of files a run's manifest may hold.
type Budget struct{ Left int }

// NewBudget returns a budget of MaxManifestFiles.
func NewBudget() *Budget { return &Budget{Left: MaxManifestFiles} }

func (b *Budget) take() bool {
	if b.Left <= 0 {
		return false
	}
	b.Left--
	return true
}

// HashPaths walks the given host paths and records {path, size, sha256} of
// every regular file (symlinks are not followed: restic stores them as
// symlinks). skipDir (the agent state dir) is never entered. Beyond the
// budget the walk stops and truncated is true. Unreadable files are skipped
// (restic reports them itself).
func HashPaths(ctx context.Context, roots []string, skipDir string, budget *Budget) (files []ManifestFile, truncated bool, err error) {
	stop := errors.New("stop")
	for _, root := range roots {
		werr := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if err != nil {
				return nil // unreadable entry: skip
			}
			if d.IsDir() {
				if skipDir != "" && UnderDir(p, skipDir) {
					return filepath.SkipDir
				}
				return nil
			}
			if !d.Type().IsRegular() {
				return nil
			}
			if !budget.take() {
				truncated = true
				return stop
			}
			f, sz, herr := hashFile(p)
			if herr != nil {
				budget.Left++
				return nil
			}
			files = append(files, ManifestFile{Path: p, Size: sz, Sha256: f})
			return nil
		})
		if errors.Is(werr, stop) {
			break
		}
		if werr != nil {
			return files, truncated, werr
		}
	}
	return files, truncated, nil
}

func hashFile(p string) (string, int64, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

// HashTar hashes every regular file of a docker archive tar stream. Entry
// names are mapped with mapName (return "" to skip). Beyond the budget the
// remaining entries are drained and truncated is true.
func HashTar(r io.Reader, mapName func(string) string, budget *Budget) (files []ManifestFile, truncated bool, err error) {
	tr := tar.NewReader(r)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return files, truncated, nil
		}
		if err != nil {
			return files, truncated, err
		}
		if h.Typeflag != tar.TypeReg {
			continue
		}
		name := mapName(path.Clean("/" + h.Name))
		if name == "" {
			continue
		}
		if !budget.take() {
			truncated = true
			continue
		}
		hs := sha256.New()
		n, err := io.Copy(hs, tr)
		if err != nil {
			return files, truncated, err
		}
		files = append(files, ManifestFile{Path: name, Size: n, Sha256: hex.EncodeToString(hs.Sum(nil))})
	}
}

// HashSingleFromTar hashes the first regular file in a tar stream (a DB dump
// fetched from a helper) and optionally feeds each line to onLine.
func HashSingleFromTar(r io.Reader, onLine func(string)) (sha string, size int64, err error) {
	tr := tar.NewReader(r)
	for {
		h, err := tr.Next()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return "", 0, errors.New("no file in archive")
			}
			return "", 0, err
		}
		if h.Typeflag != tar.TypeReg {
			continue
		}
		hs := sha256.New()
		var src io.Reader = tr
		if onLine != nil {
			src = io.TeeReader(tr, &lineSplitter{fn: onLine})
		}
		n, err := io.Copy(hs, src)
		if err != nil {
			return "", 0, err
		}
		return hex.EncodeToString(hs.Sum(nil)), n, nil
	}
}

type lineSplitter struct {
	buf []byte
	fn  func(string)
}

func (l *lineSplitter) Write(p []byte) (int, error) {
	for _, c := range p {
		if c == '\n' {
			l.fn(string(l.buf))
			l.buf = l.buf[:0]
			continue
		}
		if len(l.buf) < 4096 {
			l.buf = append(l.buf, c)
		}
	}
	return len(p), nil
}

// Mismatch is one verify difference.
type Mismatch struct {
	Path     string `json:"path"`
	Reason   string `json:"reason"` // missing|size|sha256|rows|constraints|dump
	Expected string `json:"expected,omitempty"`
	Actual   string `json:"actual,omitempty"`
}

// MaxMismatches bounds the mismatch list in results.
const MaxMismatches = 100

// CompareFiles compares expected manifest files with actual hashes.
// actualPath maps a manifest path to where it was restored (key in actual).
// Only expected files with keep(path)==true are compared.
func CompareFiles(expected []ManifestFile, actual map[string]ManifestFile, actualPath func(string) string, keep func(string) bool) (compared int, mismatches []Mismatch) {
	for _, e := range expected {
		if keep != nil && !keep(e.Path) {
			continue
		}
		compared++
		a, ok := actual[actualPath(e.Path)]
		var m *Mismatch
		switch {
		case !ok:
			m = &Mismatch{Path: e.Path, Reason: "missing"}
		case a.Size != e.Size:
			m = &Mismatch{Path: e.Path, Reason: "size", Expected: itoa(e.Size), Actual: itoa(a.Size)}
		case a.Sha256 != e.Sha256:
			m = &Mismatch{Path: e.Path, Reason: "sha256", Expected: e.Sha256, Actual: a.Sha256}
		}
		if m != nil && len(mismatches) < MaxMismatches {
			mismatches = append(mismatches, *m)
		}
	}
	return compared, mismatches
}

// CompareTables compares exact row counts and constraint names.
func CompareTables(expected, actual []TableCount, expCons, actCons []string) (compared int, mismatches []Mismatch) {
	act := map[string]int64{}
	for _, t := range actual {
		act[t.Name] = t.Rows
	}
	for _, e := range expected {
		compared++
		a, ok := act[e.Name]
		if !ok {
			mismatches = append(mismatches, Mismatch{Path: e.Name, Reason: "missing"})
		} else if a != e.Rows {
			mismatches = append(mismatches, Mismatch{Path: e.Name, Reason: "rows", Expected: itoa(e.Rows), Actual: itoa(a)})
		}
	}
	if expCons != nil {
		have := map[string]bool{}
		for _, c := range actCons {
			have[c] = true
		}
		for _, c := range expCons {
			compared++
			if !have[c] {
				mismatches = append(mismatches, Mismatch{Path: c, Reason: "constraints"})
			}
		}
	}
	if len(mismatches) > MaxMismatches {
		mismatches = mismatches[:MaxMismatches]
	}
	return compared, mismatches
}

func itoa(n int64) string {
	var b [20]byte
	i := len(b)
	neg := n < 0
	if neg {
		n = -n
	}
	for {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
		if n == 0 {
			break
		}
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

func fileMap(files []ManifestFile) map[string]ManifestFile {
	m := make(map[string]ManifestFile, len(files))
	for _, f := range files {
		m[f.Path] = f
	}
	return m
}

func sortedUnique(xs []string) []string {
	m := map[string]bool{}
	for _, x := range xs {
		m[x] = true
	}
	out := make([]string, 0, len(m))
	for x := range m {
		out = append(out, x)
	}
	sort.Strings(out)
	return out
}

// underAny reports whether p equals or is under one of roots (empty = all).
func underAny(p string, roots []string) bool {
	if len(roots) == 0 {
		return true
	}
	for _, r := range roots {
		if p == r || strings.HasPrefix(p, strings.TrimSuffix(r, "/")+"/") {
			return true
		}
	}
	return false
}
