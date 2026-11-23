package docker

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

// P6 backup/restore Engine calls (docs/AGENT_PROTOCOL.md "Backups and restores
// (P6)"). Used ONLY by internal/backupops for its hardened helper containers,
// scratch DB containers and restore volumes/networks. There is still no exec
// endpoint: helpers run a fixed argv as their container command.

var volumeNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)

// InspectVolume returns the volume or ErrNotFound.
func (e *Engine) InspectVolume(ctx context.Context, name string) (*VolumeInfo, error) {
	if !volumeNameRe.MatchString(name) {
		return nil, fmt.Errorf("docker: invalid volume name")
	}
	var v VolumeInfo
	if err := e.call(ctx, http.MethodGet, "/volumes/"+name, nil, nil, &v); err != nil {
		return nil, err
	}
	return &v, nil
}

// CreateInternalNetwork creates an INTERNAL bridge network (no external
// connectivity) — used for the isolated ppanel-restore-<8hex> scratch networks.
func (e *Engine) CreateInternalNetwork(ctx context.Context, name string, labels map[string]string) error {
	if !RestoreNetworkRe.MatchString(name) {
		return fmt.Errorf("docker: internal networks must be named ppanel-restore-<8hex>")
	}
	body := map[string]any{"Name": name, "Driver": "bridge", "CheckDuplicate": true, "Internal": true,
		"Attachable": false, "EnableIPv6": false, "Labels": labels}
	return e.call(ctx, http.MethodPost, "/networks/create", nil, body, nil)
}

// RemoveRestoreNetwork deletes a ppanel-restore-<8hex> network (the only
// network deletion the Engine permits).
func (e *Engine) RemoveRestoreNetwork(ctx context.Context, name string) error {
	if !RestoreNetworkRe.MatchString(name) {
		return fmt.Errorf("docker: only ppanel-restore-<8hex> networks may be removed")
	}
	return e.call(ctx, http.MethodDelete, "/networks/"+name, nil, nil, nil)
}

// RemoveScratchContainer force-removes a scratch DB container INCLUDING its
// anonymous volumes (v=1; the image's VOLUME data dir). Only names matching
// ScratchNameRe are accepted here and by the transport allowlist.
func (e *Engine) RemoveScratchContainer(ctx context.Context, name string) error {
	if !ScratchNameRe.MatchString(name) {
		return fmt.Errorf("docker: not a scratch container name")
	}
	return e.call(ctx, http.MethodDelete, "/containers/"+name, url.Values{"v": {"1"}, "force": {"1"}}, nil, nil)
}

// WaitContainer blocks until the container exits (or ctx ends) and returns its
// exit code. condition=not-running also returns for a never-started container.
func (e *Engine) WaitContainer(ctx context.Context, id string) (int, error) {
	resp, err := e.do(ctx, e.long, http.MethodPost, "/containers/"+id+"/wait", url.Values{"condition": {"not-running"}}, nil, nil)
	if err != nil {
		return -1, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return -1, readErr(resp)
	}
	var out struct {
		StatusCode int `json:"StatusCode"`
		Error      *struct {
			Message string `json:"Message"`
		} `json:"Error"`
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		if ctx.Err() != nil {
			return -1, ctx.Err()
		}
		return -1, err
	}
	if err := json.Unmarshal(b, &out); err != nil {
		return -1, err
	}
	if out.Error != nil && out.Error.Message != "" {
		return out.StatusCode, &APIError{Status: 200, Message: out.Error.Message}
	}
	return out.StatusCode, nil
}

// GetArchive streams a tar of path from a container (also works for created or
// exited containers and their mounted volumes). The caller closes the reader.
func (e *Engine) GetArchive(ctx context.Context, id, path string) (io.ReadCloser, error) {
	if !strings.HasPrefix(path, "/") || strings.Contains(path, "..") {
		return nil, fmt.Errorf("docker: archive path must be absolute")
	}
	resp, err := e.do(ctx, e.long, http.MethodGet, "/containers/"+id+"/archive", url.Values{"path": {path}}, nil, nil)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		defer resp.Body.Close()
		return nil, readErr(resp)
	}
	return resp.Body, nil
}

// PutArchive extracts a tar stream into dir of a helper container (by helper
// name only, see HelperNameRe). Used to hand a DB dump to a not-yet-started
// psql/mysql helper; never to the app's own containers.
func (e *Engine) PutArchive(ctx context.Context, name, dir string, tarStream io.Reader) error {
	if !HelperNameRe.MatchString(name) {
		return fmt.Errorf("docker: archive upload is only allowed into backup helper containers")
	}
	if !strings.HasPrefix(dir, "/") || strings.Contains(dir, "..") {
		return fmt.Errorf("docker: archive dir must be absolute")
	}
	u := "http://docker/containers/" + name + "/archive?" + url.Values{"path": {dir}, "noOverwriteDirNonDir": {"1"}}.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, u, tarStream)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-tar")
	resp, err := e.long.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if strings.Contains(err.Error(), "refused (not in the container-ops allowlist)") {
			return err
		}
		return &UnavailableError{Err: err}
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return readErr(resp)
	}
	return nil
}

// Output returns up to maxBytes each of the container's stdout and stderr
// (oldest first; truncated flags report cut output). Used for helper results
// (restic --json summaries on stdout).
func (e *Engine) Output(ctx context.Context, id string, maxBytes int) (stdout, stderr string, truncated bool, err error) {
	q := url.Values{"stdout": {"1"}, "stderr": {"1"}, "timestamps": {"0"}}
	resp, err := e.do(ctx, e.hc, http.MethodGet, "/containers/"+id+"/logs", q, nil, nil)
	if err != nil {
		return "", "", false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", "", false, readErr(resp)
	}
	var so, se []byte
	add := func(dst *[]byte, b []byte) {
		room := maxBytes - len(*dst)
		if room <= 0 {
			truncated = true
			return
		}
		if len(b) > room {
			b = b[:room]
			truncated = true
		}
		*dst = append(*dst, b...)
	}
	body := bufio.NewReaderSize(io.LimitReader(resp.Body, 256<<20), 64<<10)
	if resp.Header.Get("Content-Type") == "application/vnd.docker.raw-stream" {
		b, _ := io.ReadAll(io.LimitReader(body, int64(maxBytes)+1))
		add(&so, b)
		return string(so), "", truncated, nil
	}
	hdr := make([]byte, 8)
	chunk := make([]byte, 32<<10)
	for {
		if _, rerr := io.ReadFull(body, hdr); rerr != nil {
			break
		}
		dst := &so
		if hdr[0] == 2 {
			dst = &se
		}
		size := int64(binary.BigEndian.Uint32(hdr[4:]))
		for size > 0 {
			want := int64(len(chunk))
			if size < want {
				want = size
			}
			m, rerr := io.ReadFull(body, chunk[:want])
			add(dst, chunk[:m])
			size -= int64(m)
			if rerr != nil {
				if errors.Is(rerr, io.EOF) || errors.Is(rerr, io.ErrUnexpectedEOF) {
					return string(so), string(se), truncated, nil
				}
				return string(so), string(se), truncated, rerr
			}
		}
	}
	return string(so), string(se), truncated, nil
}
