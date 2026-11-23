package container_test

import (
	"strings"
	"testing"
)

func TestLoadSpec_InvalidContainer(t *testing.T) {
	t.Parallel()
	tests := []struct{ name, content, message string }{
		{"user empty group", "user: 'root:'", "container.user"},
		{"user empty name", "user: ':root'", "container.user"},
		{"user extra colon", "user: 'a:b:c'", "container.user"},
		{"user whitespace", "user: 'a b'", "container.user"},
		{"user negative", "user: '-1'", "container.user"},
		{"user oversized UID", "user: '4294967296'", "fit uint32"},
		{"user oversized GID", "user: 'nobody:4294967296'", "fit uint32"},
		{"empty executable", "entrypoint: ['']", "entrypoint executable"},
		{"relative workdir", "workdir: app", "clean absolute POSIX path"},
		{"traversing workdir", "workdir: /app/../other", "clean absolute POSIX path"},
		{"unclean workdir", "workdir: /app//other", "clean absolute POSIX path"},
		{"trailing slash workdir", "workdir: /app/", "clean absolute POSIX path"},
		{"zero port", "ports: ['0']", "decimal ports"},
		{"out of range port", "ports: ['65536']", "invalid port number"},
		{"negative port", "ports: ['-1']", "invalid port number"},
		{"non numeric port", "ports: [http]", "invalid port number"},
		{"empty port", "ports: ['']", "invalid port number"},
		{"leading zero port", "ports: ['080']", "decimal ports"},
		{"unsupported protocol", "ports: ['80/icmp']", "protocol must be"},
		{"uppercase protocol", "ports: ['80/TCP']", "protocol must be"},
		{"empty protocol", "ports: ['80/']", "protocol must be"},
		{"extra slash protocol", "ports: ['80/tcp/foo']", "protocol must be"},
		{"duplicate port", "ports: ['80', '80']", "duplicate"},
		{"equivalent port", "ports: ['80', '80/tcp']", "duplicate"},
		{"bad signal", "stop-signal: SIGMADEUP", "stop-signal"},
		{"lowercase signal", "stop-signal: sigterm", "stop-signal"},
		{"zero signal", "stop-signal: '0'", "stop-signal"},
		{"oversized signal", "stop-signal: '65'", "stop-signal"},
		{"negative signal", "stop-signal: '-1'", "stop-signal"},
		{"zero padded signal", "stop-signal: '015'", "stop-signal"},
		{"empty env key", "env: {'': value}", "container.env key"},
		{"numeric env key", "env: {'1KEY': value}", "container.env key"},
		{"equals env key", "env: {'A=B': value}", "container.env key"},
		{"control env key", "env: {\"A\\nB\": value}", "container.env key"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec, err := loadText(t, minimalSpec+"container: {"+tt.content+"}\n")
			if err == nil || spec != nil || !strings.Contains(err.Error(), tt.message) {
				t.Fatalf("want nil spec and %q error, got %#v, %v", tt.message, spec, err)
			}
		})
	}
}

func TestLoadSpec_ContainerValidBoundaries(t *testing.T) {
	t.Parallel()
	for _, content := range []string{
		"user: ''", "user: '0'", "user: nobody", "user: 'app:staff'", "user: '0:staff'",
		"user: 'app:42'", "user: '4294967295:4294967295'", "workdir: /",
		"ports: ['1', '65535/tcp', '65535/udp']", "stop-signal: '1'", "stop-signal: '64'",
		"stop-signal: SIGKILL", "stop-signal: SIGPOLL", "stop-signal: ''",
		"env: {_KEY_1: '', lowercase: '$LITERAL'}", "entrypoint: []", "cmd: []", "env: {}",
		"cmd: ['', '$LITERAL']", "entrypoint: ['/app/server', '']",
	} {
		t.Run(content, func(t *testing.T) {
			if _, err := loadText(t, minimalSpec+"container: {"+content+"}\n"); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestLoadSpec_EnvironmentErrorsAreRedacted(t *testing.T) {
	t.Parallel()
	for range 20 {
		_, err := loadText(t, minimalSpec+"container: {env: {'2BAD': hidden, '1BAD': hidden}}")
		if err == nil || !strings.Contains(err.Error(), "container.env key") ||
			strings.Contains(err.Error(), "1BAD") || strings.Contains(err.Error(), "2BAD") || strings.Contains(err.Error(), "hidden") {
			t.Fatalf("invalid env keys must fail without echoing entries: %v", err)
		}
	}
}
