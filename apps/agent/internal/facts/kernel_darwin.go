//go:build darwin

package facts

import "syscall"

func kernelRelease() string {
	v, err := syscall.Sysctl("kern.osrelease")
	if err != nil {
		return ""
	}
	return v
}
