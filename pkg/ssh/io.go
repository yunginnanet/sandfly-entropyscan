package ssh

import (
	"errors"
	"golang.org/x/crypto/ssh"
	"io"
	"path/filepath"
	"strconv"
)

// GetSession returns a new SSH session.
func (s *SSH) GetSession() (sesh *ssh.Session, err error) {
	s.verbLn("[session] getting session...")
	if s.Closed() {
		s.verbLn("[session] parent is closed")
		return nil, io.ErrClosedPipe
	}
	if s.sesh == nil {
		s.sesh, err = s.client.NewSession()
		s.verbLn("[session] session created")
	}

	return s.sesh, nil
}

// EndSession closes the SSH session.
func (s *SSH) EndSession() (err error) {
	s.verbLn("[session] ending session...")
	if s.Closed() {
		s.verbLn("[session] parent is closed")
		return io.ErrClosedPipe
	}
	if s.sesh != nil {
		s.verbLn("[session] closing session...")
		err = s.sesh.Close()
		if err != nil {
			s.verbLn("[session] error closing session:", err)
		}
		s.sesh = nil
	}

	s.verbLn("[session] session ended")
	return err
}

// ReadProc reads the executable of a process from the remote host.
func (s *SSH) ReadProc(pid int) (path string, data []byte, err error) {
	s.verbLn("[io] reading procfs, PID %d...", pid)
	if s.Closed() {
		s.verbLn("[io] parent is closed")
		return "", nil, io.ErrClosedPipe
	}

	var sesh *ssh.Session

	if sesh, err = s.GetSession(); err != nil {
		return "", nil, err
	}

	procFSPath := filepath.Join("/proc", strconv.Itoa(pid), "exe")

	var pthB = []byte(procFSPath)

	rlCmd := "readlink -f " + procFSPath

	s.verbLn(rlCmd)

	if pthB, err = sesh.Output(rlCmd); err != nil {
		s.verbLn("[io] readlink -f error: %s", err)
		pthB = []byte(procFSPath)
	}

	path = string(pthB)

	s.verbLn("[io] procfs path: %s", path)

	catCmd := "cat " + procFSPath

	s.verbLn(catCmd)

	data, err = sesh.Output(catCmd)

	return path, data, errors.Join(err, s.EndSession())
}
