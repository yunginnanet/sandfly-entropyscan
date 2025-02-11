package ssh

import (
	"errors"
	"fmt"
	"golang.org/x/crypto/ssh"
	"log"
	"sync/atomic"
	"time"
)

//goland:noinspection GoExportedElementShouldHaveComment
const (
	DefaultSSHPort        = 22
	DefaultSSHVersion     = "SSH-2.0-SF"
	DefaultSessionPrewarm = 50
)

// SSH is a struct that enables using SSH for remote agent-less entropy scanning.
type SSH struct {
	host           string
	user           string
	ver            string
	port           int
	conn           ssh.Conn
	tout           time.Duration
	auth           []ssh.AuthMethod
	client         *ssh.Client
	closed         *atomic.Bool
	sessions       chan *ssh.Session
	sessionPrewarm int
	verbose        int
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
		host:           host,
		port:           DefaultSSHPort,
		ver:            DefaultSSHVersion,
		user:           user,
		tout:           20 * time.Second,
		auth:           make([]ssh.AuthMethod, 0),
		closed:         new(atomic.Bool),
		sessions:       make(chan *ssh.Session, 50),
		sessionPrewarm: DefaultSessionPrewarm,
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

// WithSessionPrewarm sets the number of sessions to create ahead of time.
func (s *SSH) WithSessionPrewarm(n int) *SSH {
	s.sessionPrewarm = n
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
	s.traceLn("closing SSH connection")
	s.closed.Store(true)

	var err error

	close(s.sessions)

	for sesh := range s.sessions {
		cerr := sesh.Close()
		err = errors.Join(err, cerr)
	}

	if s.client != nil {
		ccerr := s.client.Close()
		err = errors.Join(err, ccerr)
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

	s.verbLn("connecting to %s:%d...", s.host, s.port)

	var err error
	if s.client, err = ssh.Dial("tcp", s.host+":"+fmt.Sprintf("%d", s.port), config); err != nil {
		s.verbLn("error connecting: %v", err)
		return err
	}

	s.verbLn("connected!")

	s.verbLn("waiting for session creation...")
	go s.createSessions()
	time.Sleep(2 * time.Second)

	s.closed.Store(false)

	return nil
}

// Closed returns true if the SSH connection is closed.
func (s *SSH) Closed() bool {
	return s.closed.Load() || s.conn == nil && s.client == nil
}
