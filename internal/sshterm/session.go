package sshterm

import (
	"fmt"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

type Session struct {
	ID        string
	Client    *ssh.Client
	CreatedAt time.Time
	Host      string
	Port      int
	Username  string
}

type SessionManager struct {
	mu       sync.RWMutex
	sessions map[string]*Session
}

var Manager = &SessionManager{
	sessions: make(map[string]*Session),
}

func (sm *SessionManager) Create(id string, client *ssh.Client, host string, port int, username string) *Session {
	s := &Session{
		ID:        id,
		Client:    client,
		CreatedAt: time.Now(),
		Host:      host,
		Port:      port,
		Username:  username,
	}
	sm.mu.Lock()
	sm.sessions[id] = s
	sm.mu.Unlock()
	return s
}

func (sm *SessionManager) Get(id string) (*Session, error) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	s, ok := sm.sessions[id]
	if !ok {
		return nil, fmt.Errorf("session %s not found", id)
	}
	return s, nil
}

func (sm *SessionManager) Remove(id string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	if s, ok := sm.sessions[id]; ok {
		s.Client.Close()
		delete(sm.sessions, id)
	}
}
