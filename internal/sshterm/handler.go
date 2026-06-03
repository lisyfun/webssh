package sshterm

import (
	"fmt"
	"time"

	"golang.org/x/crypto/ssh"
)

type ConnectParams struct {
	SessionID  string
	Host       string
	Port       int
	Username   string
	Password   string
	PrivateKey string
}

func DialSSH(params *ConnectParams) (*ssh.Client, *ssh.ClientConfig, error) {
	config := &ssh.ClientConfig{
		User:            params.Username,
		HostKeyCallback: hostKeyCallback,
		Timeout:         10 * time.Second,
	}

	if params.Password != "" {
		config.Auth = []ssh.AuthMethod{ssh.Password(params.Password)}
	} else if params.PrivateKey != "" {
		signer, err := ssh.ParsePrivateKey([]byte(params.PrivateKey))
		if err != nil {
			return nil, nil, fmt.Errorf("parse private key: %w", err)
		}
		config.Auth = []ssh.AuthMethod{ssh.PublicKeys(signer)}
	}

	addr := fmt.Sprintf("%s:%d", params.Host, params.Port)
	client, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		return nil, nil, err
	}
	return client, config, nil
}
