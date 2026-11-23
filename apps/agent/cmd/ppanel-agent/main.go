// Command ppanel-agent is the pPanel managed-host agent.
//
//	ppanel-agent enroll --center https://center:4000 --token ppe_... [--state-dir DIR]
//	ppanel-agent run [--config /etc/ppanel-agent/config.yaml]
//	ppanel-agent check-config [--config FILE]
//	ppanel-agent version
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/ppanel/ppanel/apps/agent/internal/agent"
	"github.com/ppanel/ppanel/apps/agent/internal/config"
	"github.com/ppanel/ppanel/apps/agent/internal/containerops"
	"github.com/ppanel/ppanel/apps/agent/internal/docker"
	"github.com/ppanel/ppanel/apps/agent/internal/enroll"
	"github.com/ppanel/ppanel/apps/agent/internal/execx"
	"github.com/ppanel/ppanel/apps/agent/internal/handlers"
	"github.com/ppanel/ppanel/apps/agent/internal/host"
	"github.com/ppanel/ppanel/apps/agent/internal/jobs"
	"github.com/ppanel/ppanel/apps/agent/internal/metrics"
	"github.com/ppanel/ppanel/apps/agent/internal/nginxops"
	"github.com/ppanel/ppanel/apps/agent/internal/state"
	"github.com/ppanel/ppanel/apps/agent/internal/transport"
	"github.com/ppanel/ppanel/apps/agent/internal/version"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func usage(w io.Writer) {
	fmt.Fprint(w, `usage: ppanel-agent <command> [flags]

commands:
  enroll        enroll this host with a pPanel Center (one-time token)
  run           run the agent (heartbeat, task polling)
  check-config  validate config file and state directory
  version       print version information
`)
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return 2
	}
	switch args[0] {
	case "version", "--version", "-v":
		fmt.Fprintf(stdout, "ppanel-agent %s (commit %s, built %s, protocol %s, %s %s/%s)\n",
			version.Version, version.Commit, version.BuildDate, version.ProtocolVersion, runtime.Version(), runtime.GOOS, runtime.GOARCH)
		return 0
	case "enroll":
		return cmdEnroll(args[1:], stdout, stderr)
	case "run":
		return cmdRun(args[1:], stderr)
	case "check-config":
		return cmdCheck(args[1:], stdout, stderr)
	case "help", "-h", "--help":
		usage(stdout)
		return 0
	}
	fmt.Fprintf(stderr, "unknown command %q\n", args[0])
	usage(stderr)
	return 2
}

// NewLogger returns a structured JSON logger {level, message, timestamp, ...}.
func NewLogger(w io.Writer, level string) *slog.Logger {
	var lv slog.Level
	_ = lv.UnmarshalText([]byte(level))
	return slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{Level: lv, ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
		if len(groups) > 0 {
			return a
		}
		switch a.Key {
		case slog.TimeKey:
			a.Key = "timestamp"
			a.Value = slog.StringValue(a.Value.Time().UTC().Format(time.RFC3339Nano))
		case slog.MessageKey:
			a.Key = "message"
		case slog.LevelKey:
			a.Value = slog.StringValue(strings.ToLower(a.Value.String()))
		}
		return a
	}}))
}

func cmdEnroll(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("enroll", flag.ContinueOnError)
	fs.SetOutput(stderr)
	center := fs.String("center", "", "Center API base URL, e.g. https://center.example:4000")
	token := fs.String("token", "", "one-time enrollment token (or env PPANEL_ENROLL_TOKEN)")
	cfgPath := fs.String("config", config.DefaultPath, "config file (for stateDir/centerUrl defaults)")
	stateDir := fs.String("state-dir", "", "state directory (overrides config)")
	caFile := fs.String("ca-file", "", "PEM CA to trust for the Center API (default: system roots)")
	force := fs.Bool("force", false, "re-enroll even if an identity exists")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if *stateDir != "" {
		cfg.StateDir = *stateDir
	}
	if *center == "" {
		*center = cfg.CenterURL
	}
	if *token == "" {
		*token = os.Getenv("PPANEL_ENROLL_TOKEN")
	}
	if *center == "" || *token == "" {
		fmt.Fprintln(stderr, "enroll: --center and --token are required")
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	id, err := enroll.Run(ctx, enroll.Options{CenterURL: *center, Token: *token, StateDir: cfg.StateDir, CAFile: *caFile, Force: *force})
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	fmt.Fprintf(stdout, "enrolled: serverId=%s gateway=%s stateDir=%s\n", id.ServerID, id.GatewayURL, cfg.StateDir)
	return 0
}

func loadCfg(args []string, name string, stderr io.Writer) (*config.Config, *flag.FlagSet, bool) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", config.DefaultPath, "config file (YAML or JSON)")
	stateDir := fs.String("state-dir", "", "state directory (overrides config)")
	if err := fs.Parse(args); err != nil {
		return nil, nil, false
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return nil, nil, false
	}
	if *stateDir != "" {
		cfg.StateDir = *stateDir
		if err := cfg.Validate(); err != nil {
			fmt.Fprintln(stderr, err)
			return nil, nil, false
		}
	}
	return cfg, fs, true
}

func cmdCheck(args []string, stdout, stderr io.Writer) int {
	cfg, _, ok := loadCfg(args, "check-config", stderr)
	if !ok {
		return 1
	}
	units, err := cfg.OwnedUnitSet()
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	dir := state.Dir{Path: cfg.StateDir}
	report := map[string]any{"config": "ok", "stateDir": cfg.StateDir, "enrolled": dir.Enrolled(), "ownedUnits": len(units)}
	if _, err := os.Stat(cfg.StateDir); err == nil {
		if err := dir.CheckPerms(); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
	}
	if dir.Enrolled() {
		if _, _, leaf, err := dir.LoadTLS(); err != nil {
			fmt.Fprintln(stderr, "identity:", err)
			return 1
		} else {
			report["certNotAfter"] = leaf.NotAfter.UTC().Format(time.RFC3339)
		}
	}
	b, _ := json.MarshalIndent(report, "", "  ")
	fmt.Fprintln(stdout, string(b))
	return 0
}

func cmdRun(args []string, stderr io.Writer) int {
	cfg, _, ok := loadCfg(args, "run", stderr)
	if !ok {
		return 1
	}
	log := NewLogger(stderr, cfg.LogLevel)
	if _, err := cfg.OwnedUnitSet(); err != nil {
		log.Error("owned units invalid", "error", err.Error())
		return 1
	}
	env := &host.Env{Exec: execx.System{}, Docker: docker.New(cfg.DockerSocket), NginxBinary: cfg.NginxBinary,
		SystemctlBinary: cfg.SystemctlBinary, PhpFpmPoolGlob: cfg.PhpFpmPoolGlob}
	sampler := &metrics.Sampler{}
	reg := jobs.NewRegistry()
	ngx, err := nginxops.New(nginxops.Options{Root: cfg.Nginx.Root, AllowedRoots: cfg.Nginx.AllowedRoots,
		StateDir: cfg.StateDir, NginxBinary: cfg.NginxBinary, SystemctlBinary: cfg.SystemctlBinary,
		Prefix: cfg.Nginx.Prefix, ConfFile: cfg.Nginx.ConfFile, Exec: execx.System{}})
	if err != nil {
		log.Error("nginx operations config invalid", "error", err.Error())
		return 1
	}
	// container.* jobs: the ONLY user of the write-capable Engine client; the secrets
	// channel is wired once the agent (mTLS gateway client) exists.
	var a *agent.Agent
	ctr := containerops.New(containerops.Options{Engine: docker.NewEngine(cfg.DockerSocket), Log: log.With("component", "containers"),
		Secrets: func(ctx context.Context) (*transport.JobSecrets, error) { return a.FetchJobSecrets(ctx) }})
	handlers.RegisterAll(reg, &handlers.Deps{Host: env, Sampler: sampler, OwnedUnits: cfg.OwnedUnitSet, Nginx: ngx, Containers: ctr})
	a, err = agent.New(agent.Options{Config: cfg, Registry: reg, Host: env, Sampler: sampler, Logger: log})
	if err != nil {
		log.Error("agent init failed", "error", err.Error())
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := a.Run(ctx); err != nil {
		log.Error("agent exited", "error", err.Error())
		return 1
	}
	return 0
}
