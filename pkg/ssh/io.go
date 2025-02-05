package ssh

import (
	"errors"
	"golang.org/x/crypto/ssh"
	"io"
	"path/filepath"
	"strconv"
	"sync"
)

func (s *SSH) procReadLink(sesh *ssh.Session, pid int) (procfs, abs string) {
	procFSPath := filepath.Join("/proc", strconv.Itoa(pid), "exe")
	var pthB = []byte(procFSPath)
	rlCmd := "readlink -f " + procFSPath
	var err error
	if pthB, err = s.Run(sesh, rlCmd); err != nil {
		s.verbLn("[io] readlink -f error: %s", err)
		pthB = []byte(procFSPath)
	}
	return procFSPath, string(pthB)
}

// GetSessions returns a slice of SSH sessions.
// It creates the sessions concurrently.
func (s *SSH) GetSessions(i int) ([]*ssh.Session, error) {
	var wg = new(sync.WaitGroup)
	wg.Add(i)
	var seshi = make([]*ssh.Session, i)
	var errs = make([]error, i)
	for j := 0; j < i; j++ {
		if s.Closed() {
			s.verbLn("[session] parent is closed")
			return nil, io.ErrClosedPipe
		}
		go func(e int) {
			s.traceLn("[session] creating session %d", e)
			seshi[e], errs[e] = s.client.NewSession()
			wg.Done()
		}(j)
	}
	wg.Wait()
	return seshi, errors.Join(errs...)
}

// CloseSessions closes a slice of SSH sessions.
func (s *SSH) CloseSessions(sesh []*ssh.Session) error {
	var wg = new(sync.WaitGroup)
	wg.Add(len(sesh))
	var errs = make([]error, len(sesh))
	for j := 0; j < len(sesh); j++ {
		if s.Closed() {
			s.verbLn("[session] parent is closed")
			return io.ErrClosedPipe
		}
		go func(e int) {
			if sesh[e] == nil {
				s.traceLn("[session] session %d is nil", e)
				wg.Done()
				return
			}
			s.traceLn("[session] closing session %d", e)
			errs[e] = sesh[e].Close()
			wg.Done()
		}(j)
	}
	wg.Wait()
	return errors.Join(errs...)
}

// ReadProc reads the executable of a process from the remote host.
func (s *SSH) ReadProc(pid int) (path string, data []byte, err error) {
	s.traceLn("[io] reading procfs, PID %d...", pid)
	if s.Closed() {
		s.verbLn("[io] parent is closed")
		return "", nil, io.ErrClosedPipe
	}

	seshi, err := s.GetSessions(2)
	if err != nil {
		return "", nil, err
	}

	proc, abs := s.procReadLink(seshi[0], pid)
	data, err = s.Run(seshi[1], "cat "+proc)

	return abs, data, err
}

// Run executes a command on the remote host.
func (s *SSH) Run(sesh *ssh.Session, cmd string) (output []byte, err error) {
	s.verbLn("$ " + cmd)
	output, err = sesh.Output(cmd)
	cerr := sesh.Close()
	return output, errors.Join(err, cerr)
}
