package ssh

import (
	"fmt"
	"golang.org/x/crypto/ssh"
	"sync/atomic"
	"time"
)

const (
	DefaultSSHPort    = 22
	DefaultSSHVersion = "SSH-2.0-SF"
)

// SSH is a struct that enables using SSH for remote agent-less entropy scanning.
type SSH struct {
	host   string
	user   string
	ver    string
	port   int
	conn   *ssh.Conn
	tout   time.Duration
	auth   []ssh.AuthMethod
	sesh   *ssh.Session
	client *ssh.Client
	closed *atomic.Bool
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

// Close closes the SSH connection.
func (s *SSH) Close() error {
	s.closed.Store(true)
	if s.conn == nil {
		return nil
	}
	return s.client.Close()
}

// Connect establishes an SSH connection.
func (s *SSH) Connect() error {
	if s.conn != nil {
		return nil
	}

	config := &ssh.ClientConfig{
		User:            s.user,
		Auth:            s.auth,
		ClientVersion:   s.ver,
		Timeout:         s.tout,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		BannerCallback:  ssh.BannerDisplayStderr(),
	}

	config.SetDefaults()

	var err error
	if s.client, err = ssh.Dial("tcp", s.host+":"+fmt.Sprintf("%d", s.port), config); err != nil {
		return err
	}

	s.closed.Store(false)

	return nil
}

// Closed returns true if the SSH connection is closed.
func (s *SSH) Closed() bool {
	return !s.closed.Load() && s.conn != nil && s.client != nil
}
