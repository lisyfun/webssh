package store

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"io"
	"time"

	"golang.org/x/crypto/bcrypt"

	_ "modernc.org/sqlite"
)

type Server struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Host       string `json:"host"`
	Port       int    `json:"port"`
	User       string `json:"user"`
	AuthType   string `json:"authType"`
	Password   string `json:"password,omitempty"`
	PrivateKey string `json:"privateKey,omitempty"`
	CreatedAt  string `json:"createdAt"`
	UpdatedAt  string `json:"updatedAt"`
}

type Store struct {
	db *sql.DB
	ae cipher.AEAD
}

var ErrUserNotFound = errors.New("user not found")

func New(dbPath string) (*Store, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, err
	}
	db.Exec("PRAGMA journal_mode=WAL")
	db.Exec("PRAGMA busy_timeout=5000")

	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	if err := s.initEncryptionKey(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) migrate() error {
	_, err := s.db.Exec(`
		CREATE TABLE IF NOT EXISTS config (
			key TEXT PRIMARY KEY,
			value BLOB NOT NULL
		);
		CREATE TABLE IF NOT EXISTS servers (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL DEFAULT '',
			host TEXT NOT NULL,
			port INTEGER NOT NULL DEFAULT 22,
			user TEXT NOT NULL DEFAULT 'root',
			auth_type TEXT NOT NULL DEFAULT 'password',
			password_enc BLOB NOT NULL DEFAULT '',
			private_key_enc BLOB NOT NULL DEFAULT '',
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL
		);
		CREATE TABLE IF NOT EXISTS users (
			username TEXT PRIMARY KEY,
			password_hash TEXT NOT NULL,
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL
		)
	`)
	return err
}

func (s *Store) initEncryptionKey() error {
	var keyBase64 string
	err := s.db.QueryRow("SELECT value FROM config WHERE key='encryption_key'").Scan(&keyBase64)
	if err == nil {
		data, err := base64.StdEncoding.DecodeString(keyBase64)
		if err != nil {
			return err
		}
		block, err := aes.NewCipher(data)
		if err != nil {
			return err
		}
		s.ae, err = cipher.NewGCM(block)
		return err
	}

	key := make([]byte, 32)
	io.ReadFull(rand.Reader, key)
	enc := base64.StdEncoding.EncodeToString(key)
	_, err = s.db.Exec("INSERT INTO config (key, value) VALUES ('encryption_key', ?)", enc)
	if err != nil {
		return err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	s.ae, err = cipher.NewGCM(block)
	return err
}

func (s *Store) encrypt(plaintext string) string {
	if plaintext == "" {
		return ""
	}
	nonce := make([]byte, s.ae.NonceSize())
	io.ReadFull(rand.Reader, nonce)
	ciphertext := s.ae.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext)
}

func (s *Store) decrypt(ciphertext string) string {
	if ciphertext == "" {
		return ""
	}
	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return ""
	}
	nonceSize := s.ae.NonceSize()
	if len(data) < nonceSize {
		return ""
	}
	nonce, ct := data[:nonceSize], data[nonceSize:]
	plaintext, err := s.ae.Open(nil, nonce, ct, nil)
	if err != nil {
		return ""
	}
	return string(plaintext)
}

// ---- User operations ----

func (s *Store) EnsureUser(ctx context.Context, username, password string) error {
	var existing int
	s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM users WHERE username=?", username).Scan(&existing)
	if existing > 0 {
		return nil
	}
	return s.createUser(ctx, username, password)
}

func (s *Store) createUser(ctx context.Context, username, password string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	now := time.Now().UTC().Format(time.RFC3339)
	_, err = s.db.ExecContext(ctx,
		"INSERT INTO users (username, password_hash, created_at, updated_at) VALUES (?, ?, ?, ?)",
		username, string(hash), now, now)
	return err
}

func (s *Store) VerifyPassword(ctx context.Context, username, password string) bool {
	var hash string
	err := s.db.QueryRowContext(ctx, "SELECT password_hash FROM users WHERE username=?", username).Scan(&hash)
	if err != nil {
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

func (s *Store) ChangePassword(ctx context.Context, username, oldPassword, newPassword string) error {
	if !s.VerifyPassword(ctx, username, oldPassword) {
		return errors.New("旧密码错误")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	now := time.Now().UTC().Format(time.RFC3339)
	_, err = s.db.ExecContext(ctx, "UPDATE users SET password_hash=?, updated_at=? WHERE username=?", string(hash), now, username)
	return err
}

// ---- Server operations ----

func (s *Store) ListServers(ctx context.Context) ([]Server, error) {
	rows, err := s.db.QueryContext(ctx,
		"SELECT id, name, host, port, user, auth_type, password_enc, private_key_enc, created_at, updated_at FROM servers ORDER BY name, host")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var servers []Server
	for rows.Next() {
		var svr Server
		var passwordEnc, privateKeyEnc string
		if err := rows.Scan(&svr.ID, &svr.Name, &svr.Host, &svr.Port, &svr.User, &svr.AuthType, &passwordEnc, &privateKeyEnc, &svr.CreatedAt, &svr.UpdatedAt); err != nil {
			return nil, err
		}
		svr.Password = s.decrypt(passwordEnc)
		svr.PrivateKey = s.decrypt(privateKeyEnc)
		servers = append(servers, svr)
	}
	return servers, nil
}

func (s *Store) GetServer(ctx context.Context, id string) (*Server, error) {
	var svr Server
	var passwordEnc, privateKeyEnc string
	err := s.db.QueryRowContext(ctx,
		"SELECT id, name, host, port, user, auth_type, password_enc, private_key_enc, created_at, updated_at FROM servers WHERE id=?",
		id).Scan(&svr.ID, &svr.Name, &svr.Host, &svr.Port, &svr.User, &svr.AuthType, &passwordEnc, &privateKeyEnc, &svr.CreatedAt, &svr.UpdatedAt)
	if err != nil {
		return nil, err
	}
	svr.Password = s.decrypt(passwordEnc)
	svr.PrivateKey = s.decrypt(privateKeyEnc)
	return &svr, nil
}

func (s *Store) CreateServer(ctx context.Context, svr *Server) error {
	now := time.Now().UTC().Format(time.RFC3339)
	svr.CreatedAt = now
	svr.UpdatedAt = now
	_, err := s.db.ExecContext(ctx,
		"INSERT INTO servers (id, name, host, port, user, auth_type, password_enc, private_key_enc, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
		svr.ID, svr.Name, svr.Host, svr.Port, svr.User, svr.AuthType, s.encrypt(svr.Password), s.encrypt(svr.PrivateKey), now, now)
	return err
}

func (s *Store) UpdateServer(ctx context.Context, svr *Server) error {
	now := time.Now().UTC().Format(time.RFC3339)
	svr.UpdatedAt = now
	_, err := s.db.ExecContext(ctx,
		"UPDATE servers SET name=?, host=?, port=?, user=?, auth_type=?, password_enc=?, private_key_enc=?, updated_at=? WHERE id=?",
		svr.Name, svr.Host, svr.Port, svr.User, svr.AuthType, s.encrypt(svr.Password), s.encrypt(svr.PrivateKey), now, svr.ID)
	return err
}

func (s *Store) DeleteServer(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM servers WHERE id=?", id)
	return err
}
