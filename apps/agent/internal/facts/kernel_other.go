//go:build !linux && !darwin

package facts

func kernelRelease() string { return "" }
