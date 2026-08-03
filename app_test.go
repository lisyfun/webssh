package main

import "testing"

func TestParseSSHConfigEntries(t *testing.T) {
	cfg := []byte(`
# comments are ignored
Host github.com
    HostName github.com
    User git

Host work
    HostName 192.168.1.10
    Port 2222
    User deploy
    IdentityFile ~/.ssh/id_ed25519
    ForwardAgent yes

Host *.example.com
    User root

Host multi
    HostName 10.0.0.5

Host with-vars
    HostName %h.local
`)
	entries := parseSSHConfigEntries(cfg)
	if len(entries) != 5 {
		t.Fatalf("want 5 entries, got %d", len(entries))
	}
	e := entries[1]
	if e.host != "work" || e.hostName != "192.168.1.10" || e.port != "2222" || e.user != "deploy" || e.identityFile != "~/.ssh/id_ed25519" {
		t.Fatalf("work entry wrong: %+v", e)
	}
	if entries[2].host != "*.example.com" {
		t.Fatalf("wildcard entry wrong: %+v", entries[2])
	}
	// multi-word Host line: only used for skip-check, host is joined
	if entries[3].host != "multi" || entries[3].hostName != "10.0.0.5" {
		t.Fatalf("multi entry wrong: %+v", entries[3])
	}
	if entries[4].hostName != "%h.local" {
		t.Fatalf("with-vars entry wrong: %+v", entries[4])
	}
}
