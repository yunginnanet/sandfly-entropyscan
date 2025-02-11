package ssh

import (
	"bytes"
	"context"
	"errors"
	"golang.org/x/crypto/ssh"
	"io"
	"path/filepath"
	"strconv"
)

const getPIDs = `bash -c 'for proc in /proc/*/exe; do if test -r "$proc" > /dev/null; then echo -n "$proc" | grep -v self | tr -d "/exeproc" | tr "\n" " "; fi; done'`

func (s *SSH) whoami(sesh *ssh.Session) (string, error) {
	var whoiam = ""
	usr, err := s.Run(sesh, "whoami")
	if usr != nil {
		whoiam = string(bytes.TrimSpace(usr))
	}
	return whoiam, err
}

// GetPIDs returns a list of process IDs from the remote host that the user has access to.
func (s *SSH) GetPIDs() ([]int, error) {
	var (
		pids = make([]int, 0)
		ps   []byte
		err  error
		sesh *ssh.Session
	)

	if sesh, err = s.GetSession(context.Background()); err != nil {
		return nil, err
	}

	if ps, err = s.Run(sesh, getPIDs); err != nil {
		return nil, err
	}

	for _, p := range bytes.Fields(ps) {
		var pid int
		if pid, err = strconv.Atoi(string(p)); err == nil {
			pids = append(pids, pid)
		}
	}

	s.verbLn("found %d PIDs with read permissions: %+v", len(pids), pids)

	return pids, nil
}

func (s *SSH) procReadLink(sesh *ssh.Session, pid int) (procfs, abs string) {
	procFSPath := filepath.Join("/proc", strconv.Itoa(pid), "exe")
	var pthB = []byte(procFSPath)

	var err error
	if pthB, err = s.Run(sesh, "readlink -f "+procFSPath); err != nil {
		pthB = []byte(procFSPath)
	}

	s.verbLn("procfs path: %s", string(pthB))

	return procFSPath, string(bytes.TrimSpace(pthB))
}

// ReadProc reads the executable of a process from the remote host.
func (s *SSH) ReadProc(pid int) (path string, data []byte, err error) {
	s.traceLn("reading procfs, PID %d...", pid)
	if s.Closed() {
		s.verbLn("parent is closed")
		return "", nil, io.ErrClosedPipe
	}

	var seshi = make([]*ssh.Session, 2)
	ctx, cancel := context.WithTimeout(context.Background(), s.tout)
	for i := range seshi {
		var sesh *ssh.Session
		if sesh, err = s.GetSession(ctx); err != nil {
			cancel()
			return "", nil, err
		}
		seshi[i] = sesh
	}

	proc, abs := s.procReadLink(seshi[0], pid)
	data, err = s.Run(seshi[1], "cat "+proc)

	cancel()
	return abs, data, err
}

// Run executes a command on the remote host.
func (s *SSH) Run(sesh *ssh.Session, cmd string) (output []byte, err error) {
	s.verbLn("$ " + cmd)
	if output, err = sesh.Output(cmd); err != nil {
		s.verbLn("run error: %s", err.Error())
	}
	if errors.Is(err, io.EOF) {
		err = nil
	}

	cerr := sesh.Close()
	if errors.Is(cerr, io.EOF) {
		cerr = nil
	}

	s.verbLn("\tresulting output: %d bytes", len(output))

	return output, errors.Join(err, cerr)
}
