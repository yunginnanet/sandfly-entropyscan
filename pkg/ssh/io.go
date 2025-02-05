package ssh

import (
	"errors"
	"golang.org/x/crypto/ssh"
	"io"
	"os"
	"path/filepath"
	"strconv"
)

// GetSession returns a new SSH session.
func (s *SSH) GetSession() (sesh *ssh.Session, err error) {
	if s.sesh == nil {
		s.sesh, err = s.client.NewSession()
		return s.sesh, err
	}
	return s.sesh, nil
}

// EndSession closes the SSH session.
func (s *SSH) EndSession() (err error) {
	if s.sesh != nil {
		err = s.sesh.Close()
		s.sesh = nil
	}
	return err
}

// ReadProc reads the executable of a process from the remote host.
func (s *SSH) ReadProc(pid int) (path string, data []byte, err error) {
	if s.Closed() {
		return "", nil, io.ErrClosedPipe
	}

	var sesh *ssh.Session

	if sesh, err = s.GetSession(); err != nil {
		return "", nil, err
	}

	procFSPath := filepath.Join("/proc", strconv.Itoa(pid), "exe")

	var pthB = []byte(procFSPath)

	if pthB, err = sesh.Output("readlink -f " + procFSPath); err != nil {
		_, _ = os.Stderr.WriteString(err.Error() + "\n")
		pthB = []byte(procFSPath)
	}

	path = string(pthB)

	data, err = sesh.Output("cat " + procFSPath)

	return path, data, errors.Join(err, s.EndSession())
}
