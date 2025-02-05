package ssh

import (
	"errors"
	"golang.org/x/crypto/ssh"
	"io"
	"path/filepath"
	"strconv"
)

// ReadProc reads the executable of a process from the remote host.
func (s *SSH) ReadProc(pid int) (path string, data []byte, err error) {
	s.traceLn("[io] reading procfs, PID %d...", pid)
	if s.Closed() {
		s.verbLn("[io] parent is closed")
		return "", nil, io.ErrClosedPipe
	}

	var sesh *ssh.Session

	if sesh, err = s.client.NewSession(); err != nil {
		return "", nil, err
	}

	procFSPath := filepath.Join("/proc", strconv.Itoa(pid), "exe")

	var pthB = []byte(procFSPath)

	rlCmd := "readlink -f " + procFSPath

	s.verbLn("$\t" + rlCmd)

	if pthB, err = sesh.Output(rlCmd); err != nil {
		s.verbLn("[io] readlink -f error: %s", err)
		pthB = []byte(procFSPath)
	}

	path = string(pthB)

	s.traceLn("[io] procfs path: %s", path)

	catCmd := "cat " + procFSPath

	s.verbLn("$\t" + catCmd)

	data, err = sesh.Output(catCmd)

	return path, data, errors.Join(err, sesh.Close())
}
