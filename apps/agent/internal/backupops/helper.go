package backupops

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"sort"
	"time"

	"github.com/ppanel/ppanel/apps/agent/internal/containerops"
	"github.com/ppanel/ppanel/apps/agent/internal/docker"
)

// Labels written on helper / scratch containers, restore volumes and networks.
const (
	LabelBackup = "ppanel.backup" // runId or restoreId
	LabelRole   = "ppanel.backup.role"
)

// Helper hardening (same baseline as container.run_candidate): no published
// ports, CapDrop ALL, no-new-privileges, memory/pids/cpu limits.
const (
	HelperMemory   = int64(1 << 30)
	HelperPids     = int64(256)
	HelperNanoCpus = int64(1e9)
	// HelperWorkDir is a writable directory of the helper image (owned by its
	// non-root user) where DB dumps are staged for the archive hand-off.
	HelperWorkDir = "/work"
	maxHelperOut  = 4 << 20
)

// Mount is a helper volume mount.
type Mount struct {
	Volume   string
	Target   string
	ReadOnly bool
}

// HelperSpec describes one helper container run (a fixed argv, no shell).
type HelperSpec struct {
	Role       string // backup|dump|query|load|restore|ready
	App        string // "" for app-independent helpers
	RunLabel   string // runId / restoreId / verify id
	Image      string
	Entrypoint []string // nil = image default (restic)
	Cmd        []string
	Env        []string // KEY=VALUE — may carry secrets (engine only)
	Mounts     []Mount
	Network    string // "bridge" | ppanel-<app> | ppanel-restore-<8hex>
	ExtraHosts []string
	User       string   // "" = image default (non-root)
	CapAdd     []string // nil = none
	// Writable rootfs (needed when output is staged in /work or a dump is
	// uploaded into the container); otherwise read-only with tmpfs /tmp.
	Writable bool
	Hostname string
}

// NewHelperName returns ppanel-bk-<16 hex>.
func NewHelperName() string { return "ppanel-bk-" + randHex(8) }

func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

// HelperCreateBody builds the hardened create body of a helper container.
func HelperCreateBody(s HelperSpec) map[string]any {
	mounts := make([]map[string]any, 0, len(s.Mounts))
	for _, m := range s.Mounts {
		mounts = append(mounts, map[string]any{"Type": "volume", "Source": m.Volume, "Target": m.Target, "ReadOnly": m.ReadOnly})
	}
	capAdd := s.CapAdd
	if capAdd == nil {
		capAdd = []string{}
	}
	extra := append([]string{}, s.ExtraHosts...)
	sort.Strings(extra)
	hc := map[string]any{
		"PortBindings":    map[string]any{},
		"PublishAllPorts": false,
		"Privileged":      false,
		"CapDrop":         []string{"ALL"},
		"CapAdd":          capAdd,
		"SecurityOpt":     containerops.SecurityOpt,
		"Memory":          HelperMemory,
		"MemorySwap":      HelperMemory,
		"NanoCpus":        HelperNanoCpus,
		"PidsLimit":       HelperPids,
		"ReadonlyRootfs":  !s.Writable,
		"RestartPolicy":   map[string]any{"Name": "no"},
		"NetworkMode":     s.Network,
		"IpcMode":         "private",
		"Mounts":          mounts,
		"ExtraHosts":      extra,
		"AutoRemove":      false,
		"LogConfig":       map[string]any{"Type": "json-file", "Config": map[string]string{"max-size": "10m", "max-file": "1"}},
	}
	if !s.Writable {
		hc["Tmpfs"] = map[string]string{"/tmp": "rw,noexec,nosuid,size=256m"}
	}
	labels := map[string]string{containerops.LabelManaged: "true", LabelBackup: s.RunLabel, LabelRole: s.Role}
	if s.App != "" {
		labels[containerops.LabelApp] = s.App
	}
	body := map[string]any{
		"Image":        s.Image,
		"Env":          append([]string{"HOME=/tmp"}, s.Env...),
		"Labels":       labels,
		"ExposedPorts": map[string]any{},
		"Tty":          false,
		"OpenStdin":    false,
		"AttachStdin":  false,
		"AttachStdout": false,
		"AttachStderr": false,
		"StopSignal":   "SIGINT", // restic removes its lock on SIGINT
		"StopTimeout":  20,
		"Cmd":          s.Cmd,
		"HostConfig":   hc,
	}
	if s.Entrypoint != nil {
		body["Entrypoint"] = s.Entrypoint
	}
	if s.User != "" {
		body["User"] = s.User
	}
	if s.Hostname != "" {
		body["Hostname"] = s.Hostname
	}
	return body
}

// HelperResult is a finished helper run.
type HelperResult struct {
	Name     string
	ID       string
	ExitCode int
	Stdout   []byte
	Stderr   []byte
}

// helperRun is a created helper container; Remove must always be called.
type helperRun struct {
	e    *docker.Engine
	name string
	id   string
	log  *slog.Logger
}

func createHelper(ctx context.Context, e *docker.Engine, s HelperSpec, log *slog.Logger) (*helperRun, error) {
	name := NewHelperName()
	id, err := e.CreateContainer(ctx, name, HelperCreateBody(s))
	if err != nil {
		return nil, err
	}
	return &helperRun{e: e, name: name, id: id, log: log}, nil
}

// startWait starts the helper and waits for it to exit. On ctx end the helper
// is stopped (SIGINT, then kill) so restic aborts without a snapshot.
func (h *helperRun) startWait(ctx context.Context) (*HelperResult, error) {
	if err := h.e.StartContainer(ctx, h.id); err != nil {
		return nil, err
	}
	code, err := h.e.WaitContainer(ctx, h.id)
	if err != nil {
		if ctx.Err() != nil {
			sctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
			_ = h.e.StopContainer(sctx, h.id, 20)
			cancel()
			return nil, ctx.Err()
		}
		return nil, err
	}
	octx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	so, se, _, oerr := h.e.Output(octx, h.id, maxHelperOut)
	if oerr != nil {
		return nil, oerr
	}
	return &HelperResult{Name: h.name, ID: h.id, ExitCode: code, Stdout: []byte(so), Stderr: []byte(se)}, nil
}

// archive streams a path out of the (exited) helper.
func (h *helperRun) archive(ctx context.Context, p string) (io.ReadCloser, error) {
	return h.e.GetArchive(ctx, h.id, p)
}

// remove force-removes the helper (background ctx: also runs after cancel).
func (h *helperRun) remove() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := h.e.RemoveContainer(ctx, h.id, true); err != nil && !errors.Is(err, docker.ErrNotFound) {
		h.log.Error("helper removal failed", "name", h.name, "error", err.Error())
	}
}

// runHelper creates, runs and removes a helper; inspect (optional) runs while
// the exited container still exists (archive reads).
func runHelper(ctx context.Context, e *docker.Engine, s HelperSpec, log *slog.Logger, inspect func(*helperRun, *HelperResult) error) (*HelperResult, error) {
	h, err := createHelper(ctx, e, s, log)
	if err != nil {
		return nil, err
	}
	defer h.remove()
	res, err := h.startWait(ctx)
	if err != nil {
		return nil, err
	}
	if inspect != nil {
		if err := inspect(h, res); err != nil {
			return res, err
		}
	}
	return res, nil
}
