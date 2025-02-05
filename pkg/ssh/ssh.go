package ssh

import (
	"fmt"
	"golang.org/x/crypto/ssh"
	"log"
	"sync/atomic"
	"time"
)

const (
	DefaultSSHPort    = 22
	DefaultSSHVersion = "SSH-2.0-SF"
)

// SSH is a struct that enables using SSH for remote agent-less entropy scanning.
type SSH struct {
	host    string
	user    string
	ver     string
	port    int
	conn    ssh.Conn
	tout    time.Duration
	auth    []ssh.AuthMethod
	client  *ssh.Client
	closed  *atomic.Bool
	verbose int
}

func (s *SSH) String() string {
	closed := ""
	if s.closed.Load() {
		closed = " (closed)"
	}

	prefix := ""
	suffix := ""

	if s.conn != nil {
		seshID := s.conn.SessionID()
		seshIDTrunc := fmt.Sprintf("%x%x", seshID[:4], seshID[len(seshID)-4:])
		prefix = fmt.Sprintf("%s -> ", s.conn.LocalAddr())
		suffix = fmt.Sprintf(" (srv: %s) [%s]", s.conn.ServerVersion(), seshIDTrunc)
	}

	return fmt.Sprintf("%s%s@%s:%d%s%s",
		prefix, s.user, s.host, s.port, closed, suffix,
	)
}

// NewSSH substantiates a new [SSH] struct and returns a pointer to it.
func NewSSH(host string, user string) *SSH {
	s := &SSH{
		host:   host,
		port:   DefaultSSHPort,
		ver:    DefaultSSHVersion,
		user:   user,
		tout:   20 * time.Second,
		auth:   make([]ssh.AuthMethod, 0),
		closed: new(atomic.Bool),
	}
	s.closed.Store(false)
	return s
}

// WithVerbose increases the verbosity of SSH operations.
func (s *SSH) WithVerbose(i int) *SSH {
	s.verbose = i
	return s
}

// WithPort sets the port for the SSH connection.
func (s *SSH) WithPort(port int) *SSH {
	s.port = port
	return s
}

// WithTimeout sets the timeout for the SSH connection.
func (s *SSH) WithTimeout(tout time.Duration) *SSH {
	s.tout = tout
	return s
}

// WithVersion sets the version for the SSH connection.
func (s *SSH) WithVersion(ver string) *SSH {
	s.ver = ver
	return s
}

func (s *SSH) traceLn(fmt string, args ...any) {
	if s.verbose < 2 {
		return
	}
	log.Printf(s.String()+"> "+fmt+"\n", args...)
}

func (s *SSH) verbLn(fmt string, args ...any) {
	if s.verbose < 1 {
		return
	}
	log.Printf(s.String()+"> "+fmt+"\n", args...)
}

// Close closes the SSH connection.
func (s *SSH) Close() error {
	s.traceLn("[close] closing SSH connection")
	s.closed.Store(true)
	if s.conn == nil {
		s.traceLn("[close] SSH connection is nil")
	}
	if s.client == nil {
		s.traceLn("[close] SSH client is nil")
	}
	var err error
	if s.closed != nil {
		err = s.client.Close()
		if err != nil {
			s.verbLn("[close] error closing SSH connection: %v", err)
		}
	}
	return err
}

// Connect establishes an SSH connection.
func (s *SSH) Connect() error {
	if s.conn != nil {
		return nil
	}

	config := &ssh.ClientConfig{
		User: s.user,
		Auth: s.auth,
		// ClientVersion:   s.ver,
		Timeout:         s.tout,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		BannerCallback:  ssh.BannerDisplayStderr(),
	}

	config.SetDefaults()

	s.verbLn("[connect] connecting...", s.host, s.port)

	var err error
	if s.client, err = ssh.Dial("tcp", s.host+":"+fmt.Sprintf("%d", s.port), config); err != nil {
		s.verbLn("[connect] error connecting: %v", err)
		return err
	}

	s.conn = s.client.Conn
	s.closed.Store(false)

	s.verbLn("[connect] connected!")

	return nil
}

// Closed returns true if the SSH connection is closed.
func (s *SSH) Closed() bool {
	return s.closed.Load() || s.conn == nil && s.client == nil
}
