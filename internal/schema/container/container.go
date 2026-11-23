// Package container defines OCI runtime configuration for the image.
package container

import (
	"errors"
	"fmt"
	"path"
	"strconv"
	"strings"

	"github.com/matt-mai/vapor/internal/schema/base"
)

// Container holds OCI runtime configuration; omitted fields remain unset.
type Container struct {
	User       string            `yaml:"user" json:"user"`
	Entrypoint []string          `yaml:"entrypoint" json:"entrypoint"`
	Cmd        []string          `yaml:"cmd" json:"cmd"`
	Workdir    string            `yaml:"workdir" json:"workdir"`
	Ports      []string          `yaml:"ports" json:"ports"`
	StopSignal string            `yaml:"stop-signal" json:"stop-signal"`
	Env        map[string]string `yaml:"env" json:"env"`
}

type inputError struct {
	message string
	cause   error
}

func (e *inputError) Error() string { return e.message }
func (e *inputError) Unwrap() error { return e.cause }

// Validate checks OCI runtime fields for supported values and consistency.
func Validate(container *Container) error {
	if err := validateUser(container.User); err != nil {
		return err
	}
	if len(container.Entrypoint) > 0 && container.Entrypoint[0] == "" {
		return errors.New("container.entrypoint executable must not be empty")
	}
	if container.Workdir != "" && (!path.IsAbs(container.Workdir) || path.Clean(container.Workdir) != container.Workdir) {
		return errors.New("container.workdir must be a clean absolute POSIX path")
	}
	if err := validatePorts(container.Ports); err != nil {
		return err
	}
	if err := validateStopSignal(container.StopSignal); err != nil {
		return err
	}
	for key := range container.Env {
		if err := base.RequirePattern("container.env key", key, `^[A-Za-z_][A-Za-z0-9_]*$`); err != nil {
			return err
		}
	}
	return nil
}

func validateUser(user string) error {
	if user == "" {
		return nil
	}
	parts := strings.Split(user, ":")
	if len(parts) > 2 {
		return errors.New("container.user must be user[:group]")
	}
	for _, part := range parts {
		if err := base.RequirePattern("container.user", part, `^([0-9]+|[A-Za-z_][A-Za-z0-9_.-]*)$`); err != nil {
			return err
		}
		if part[0] >= '0' && part[0] <= '9' {
			if _, err := strconv.ParseUint(part, 10, 32); err != nil {
				return &inputError{message: "container.user ID must fit uint32", cause: err}
			}
		}
	}
	return nil
}

func validatePorts(ports []string) error {
	seen := make(map[string]bool)
	for _, port := range ports {
		key, err := validatePort(port)
		if err != nil {
			return err
		}
		if seen[key] {
			return fmt.Errorf("container.ports: duplicate %q", key)
		}
		seen[key] = true
	}
	return nil
}

func validatePort(port string) (string, error) {
	number, protocol, explicit := strings.Cut(port, "/")
	if !explicit {
		protocol = "tcp"
	}
	n, err := strconv.ParseUint(number, 10, 16)
	if err != nil {
		return "", &inputError{message: "container.ports: invalid port number", cause: err}
	}
	if n == 0 || strconv.FormatUint(n, 10) != number {
		return "", errors.New("container.ports must use decimal ports 1–65535 without leading zeros")
	}
	if protocol != "tcp" && protocol != "udp" && protocol != "sctp" {
		return "", errors.New("container.ports protocol must be tcp, udp or sctp")
	}
	return number + "/" + protocol, nil
}

func validateStopSignal(signal string) error {
	switch signal {
	case "", "SIGHUP", "SIGINT", "SIGQUIT", "SIGILL", "SIGTRAP", "SIGABRT", "SIGIOT",
		"SIGBUS", "SIGFPE", "SIGKILL", "SIGUSR1", "SIGSEGV", "SIGUSR2", "SIGPIPE",
		"SIGALRM", "SIGTERM", "SIGSTKFLT", "SIGCHLD", "SIGCLD", "SIGCONT", "SIGSTOP",
		"SIGTSTP", "SIGTTIN", "SIGTTOU", "SIGURG", "SIGXCPU", "SIGXFSZ", "SIGVTALRM",
		"SIGPROF", "SIGWINCH", "SIGIO", "SIGPOLL", "SIGPWR", "SIGSYS":
		return nil
	}
	n, err := strconv.Atoi(signal)
	if err != nil || n < 1 || n > 64 || strconv.Itoa(n) != signal {
		return errors.New("container.stop-signal must be a Linux SIG name or decimal number 1–64")
	}
	return nil
}
