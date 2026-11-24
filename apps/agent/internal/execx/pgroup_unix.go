//go:build unix

package execx

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
)

func setProcessGroup(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setpgid = true
}

// signalGroup sends sig to the process group led by cmd's process. It is a
// no-op before start; ESRCH (group already gone) is not an error.
func signalGroup(cmd *exec.Cmd, sig os.Signal) error {
	if cmd.Process == nil {
		return nil
	}
	s, ok := sig.(syscall.Signal)
	if !ok {
		s = syscall.SIGKILL
	}
	pid := cmd.Process.Pid
	if pid <= 1 {
		return nil
	}
	err := syscall.Kill(-pid, s)
	if errors.Is(err, syscall.ESRCH) {
		return nil
	}
	if err != nil {
		// fall back to the leader only
		return cmd.Process.Signal(sig)
	}
	return nil
}
