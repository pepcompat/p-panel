package agent

import "os"

func exists(p string) bool     { _, err := os.Stat(p); return err == nil }
func rename(a, b string) error { return os.Rename(a, b) }
func remove(p string) error    { return os.Remove(p) }
