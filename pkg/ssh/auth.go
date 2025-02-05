package ssh

import (
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"net"
	"os"
)

// WithAuth adds authentication methods to the [SSH] struct.
func (s *SSH) WithAuth(auth ...ssh.AuthMethod) *SSH {
	s.auth = append(s.auth, auth...)
	return s
}

// WithPassword adds a password callback to the SSH struct for authentication.
func (s *SSH) WithPassword(password string) *SSH {
	s.auth = append(s.auth, ssh.Password(password))
	return s
}

// WithKey parses data from an SSH key to extract signers for authentication.
func (s *SSH) WithKey(key []byte) *SSH {
	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		_, _ = os.Stdout.WriteString(err.Error() + "\n")
		return s
	}
	s.auth = append(s.auth, ssh.PublicKeys(signer))
	return s
}

// WithKeyFile parses data from an SSH to be processed by [s.WithKey].
func (s *SSH) WithKeyFile(path string) *SSH {
	dat, err := os.ReadFile(path)
	if err != nil {
		_, _ = os.Stdout.WriteString(err.Error() + "\n")
		return s
	}
	return s.WithKey(dat)
}

// WithAgent adds all available signers from an SSH agent to the [SSH] struct for authentication. (*nix)
func (s *SSH) WithAgent() *SSH {
	agentURI := os.Getenv("SSH_AUTH_SOCK")
	conn, err := net.Dial("unix", agentURI)
	if err != nil {
		_, _ = os.Stdout.WriteString(err.Error() + "\n")
		return s
	}
	sshAgent := agent.NewClient(conn)
	signers, serr := sshAgent.Signers()
	if serr != nil {
		_, _ = os.Stdout.WriteString(serr.Error() + "\n")
		_ = conn.Close()
		return s
	}

	s.auth = append(s.auth, ssh.PublicKeys(signers...))

	_ = conn.Close()

	return s
}
