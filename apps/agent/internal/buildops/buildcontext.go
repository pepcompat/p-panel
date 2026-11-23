package buildops

import (
	"archive/tar"
	"bufio"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// DefaultMaxContextBytes caps the build context (sum of regular file sizes).
const DefaultMaxContextBytes int64 = 500 << 20

// errContextTooLarge / errEscape are mapped to SOURCE_FETCH_FAILED.
var (
	errContextTooLarge = errors.New("build context larger than the limit")
	errEscape          = errors.New("path escapes the checkout")
)

// within reports whether p (clean, absolute) is root or below root.
func within(root, p string) bool {
	rel, err := filepath.Rel(root, p)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}

// resolveInside resolves rel under root following symlinks; the result must
// stay inside root (symlinks escaping the checkout are refused).
func resolveInside(root, rel string) (string, error) {
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", err
	}
	if rel == "" {
		return realRoot, nil
	}
	real, err := filepath.EvalSymlinks(filepath.Join(realRoot, filepath.FromSlash(rel)))
	if err != nil {
		return "", err
	}
	if !within(realRoot, real) {
		return "", errEscape
	}
	return real, nil
}

// ---------------- .dockerignore ----------------

type ignoreRule struct {
	re  *regexp.Regexp
	neg bool
}

type ignorer struct {
	rules  []ignoreRule
	hasNeg bool
}

// compileIgnore converts one .dockerignore pattern into an anchored regexp
// (`**` any number of path segments, `*` / `?` within a segment, [classes]).
func compileIgnore(p string) (*regexp.Regexp, error) {
	var b strings.Builder
	b.WriteString("^")
	for i := 0; i < len(p); i++ {
		c := p[i]
		switch c {
		case '*':
			if i+1 < len(p) && p[i+1] == '*' {
				i++
				if i+1 < len(p) && p[i+1] == '/' {
					i++
					b.WriteString("(.*/)?")
				} else {
					b.WriteString(".*")
				}
			} else {
				b.WriteString("[^/]*")
			}
		case '?':
			b.WriteString("[^/]")
		case '[':
			j := strings.IndexByte(p[i:], ']')
			if j < 0 {
				return nil, fmt.Errorf("bad pattern %q", p)
			}
			cls := p[i+1 : i+j]
			if strings.HasPrefix(cls, "!") {
				cls = "^" + cls[1:]
			}
			b.WriteString("[" + strings.ReplaceAll(cls, `\`, `\\`) + "]")
			i += j
		case '\\':
			if i+1 < len(p) {
				i++
				b.WriteString(regexp.QuoteMeta(string(p[i])))
			}
		default:
			b.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	b.WriteString("$")
	return regexp.Compile(b.String())
}

func loadIgnore(root string) (*ignorer, error) {
	ig := &ignorer{}
	f, err := os.Open(filepath.Join(root, ".dockerignore"))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return ig, nil
		}
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		return ig, nil
	}
	sc := bufio.NewScanner(io.LimitReader(f, 256<<10))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		neg := strings.HasPrefix(line, "!")
		if neg {
			line = strings.TrimSpace(line[1:])
		}
		line = path.Clean(strings.TrimPrefix(filepath.ToSlash(line), "/"))
		if line == "." || line == "" {
			continue
		}
		re, err := compileIgnore(line)
		if err != nil {
			return nil, err
		}
		ig.rules = append(ig.rules, ignoreRule{re: re, neg: neg})
		ig.hasNeg = ig.hasNeg || neg
	}
	return ig, sc.Err()
}

// ignored applies the rules in order (last match wins); a pattern matching a
// parent directory also matches everything below it.
func (ig *ignorer) ignored(rel string) bool {
	matched := false
	for _, r := range ig.rules {
		hit := r.re.MatchString(rel)
		if !hit {
			for dir := path.Dir(rel); dir != "." && dir != "/"; dir = path.Dir(dir) {
				if r.re.MatchString(dir) {
					hit = true
					break
				}
			}
		}
		if hit {
			matched = !r.neg
		}
	}
	return matched
}

// ---------------- tar ----------------

var fixedMtime = time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)

// contextSpec describes what writeContext puts into the tar.
type contextSpec struct {
	Root       string // resolved context directory (inside the checkout)
	Dockerfile string // relative Dockerfile path to always include ("" for templates)
	Template   []byte // template content written as Dockerfile.ppanel (nil = none)
	TemplateAs string
	MaxBytes   int64
}

// writeContext tars spec.Root into w: no .git anywhere, .dockerignore applied
// (the Dockerfile itself is always kept), symlinks only when their target stays
// inside the context, special files skipped, owner 0:0, fixed mtime.
func writeContext(spec contextSpec, w io.Writer) (files int, size int64, err error) {
	ig, err := loadIgnore(spec.Root)
	if err != nil {
		return 0, 0, fmt.Errorf(".dockerignore: %w", err)
	}
	tw := tar.NewWriter(w)
	keep := map[string]bool{spec.Dockerfile: spec.Dockerfile != "", ".dockerignore": true}
	err = filepath.WalkDir(spec.Root, func(p string, d fs.DirEntry, werr error) error {
		if werr != nil {
			return werr
		}
		if p == spec.Root {
			return nil
		}
		rel, err := filepath.Rel(spec.Root, p)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if d.Name() == ".git" {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if spec.Template != nil && rel == spec.TemplateAs {
			return nil // the embedded template wins over a repo file of the same name
		}
		if !keep[rel] && ig.ignored(rel) {
			if d.IsDir() && ig.hasNeg {
				return nil // no header; a negated file below may still be included
			}
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		hdr := &tar.Header{Name: rel, ModTime: fixedMtime, Uid: 0, Gid: 0}
		switch {
		case info.Mode().IsDir():
			hdr.Typeflag, hdr.Name, hdr.Mode = tar.TypeDir, rel+"/", 0o755
			return tw.WriteHeader(hdr)
		case info.Mode()&fs.ModeSymlink != 0:
			target, err := os.Readlink(p)
			if err != nil {
				return err
			}
			if filepath.IsAbs(target) || !within(spec.Root, filepath.Join(filepath.Dir(p), target)) {
				return fmt.Errorf("%w: symlink %s -> %s", errEscape, rel, target)
			}
			hdr.Typeflag, hdr.Linkname, hdr.Mode = tar.TypeSymlink, filepath.ToSlash(target), 0o777
			return tw.WriteHeader(hdr)
		case info.Mode().IsRegular():
			size += info.Size()
			if size > spec.MaxBytes {
				return errContextTooLarge
			}
			hdr.Typeflag, hdr.Size, hdr.Mode = tar.TypeReg, info.Size(), 0o644
			if info.Mode().Perm()&0o111 != 0 {
				hdr.Mode = 0o755
			}
			if err := tw.WriteHeader(hdr); err != nil {
				return err
			}
			f, err := os.Open(p)
			if err != nil {
				return err
			}
			n, err := io.Copy(tw, io.LimitReader(f, info.Size()))
			f.Close()
			if err != nil {
				return err
			}
			if n != info.Size() {
				return fmt.Errorf("%s changed while archiving", rel)
			}
			files++
			return nil
		default:
			return nil // fifo/socket/device: never part of a context
		}
	})
	if err != nil {
		return files, size, err
	}
	if spec.Template != nil {
		size += int64(len(spec.Template))
		hdr := &tar.Header{Name: spec.TemplateAs, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(spec.Template)), ModTime: fixedMtime}
		if err := tw.WriteHeader(hdr); err != nil {
			return files, size, err
		}
		if _, err := tw.Write(spec.Template); err != nil {
			return files, size, err
		}
		files++
	}
	return files, size, tw.Close()
}
