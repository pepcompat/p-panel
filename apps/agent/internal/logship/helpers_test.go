package logship

import (
	"os"

	"github.com/ppanel/ppanel/apps/agent/internal/config"
)

func testLogsCfg(capBytes int64, maxBatch int) config.LogsConfig {
	return config.LogsConfig{Enabled: true, BufferCapBytes: capBytes, ShipIntervalMs: 50, MaxBatchEntries: maxBatch,
		Sources: []config.LogSource{{Source: SourceAgent}}}
}

func readFile(p string) ([]byte, error) { return os.ReadFile(p) }
