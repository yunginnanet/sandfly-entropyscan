package ssh

import (
	"context"
	"golang.org/x/crypto/ssh"
	"io"
	"time"
)

func (s *SSH) createSessions() {
	s.traceLn("creating sessions...")
	for {
		if s.closed.Load() || s.client == nil {
			s.traceLn("end of session creation")
			return
		}
		time.Sleep(100 * time.Millisecond)
		sesh, err := s.client.NewSession()
		if err != nil {
			s.verbLn("error creating session: %v", err)
			time.Sleep(1 * time.Second)
			continue
		}
		select {
		case s.sessions <- sesh:
			s.traceLn("created session %p", sesh)
		default:
			_ = sesh.Close()
			time.Sleep(1 * time.Second)
		}
	}
}

// GetSession returns a session from the SSH connection.
func (s *SSH) GetSession(ctx context.Context) (*ssh.Session, error) {
	if s.closed.Load() {
		return nil, io.ErrClosedPipe
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case sesh := <-s.sessions:
		return sesh, nil
	}
}
