package ui

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestReporter_Clean(t *testing.T) {
	for _, tc := range []struct {
		name, input, want string
		secrets           []string
	}{
		{"controls", "one\n\r\x1b[31m\x00\t\u202etwo\u009b", "one   [31m   two ", nil},
		{"URL", "fetch https://user:password@example.test/a?token=secret#private", "fetch https://example.test/a", nil},
		{"bad URL", "https://user:%zz@example.test/a", "[redacted URL]", nil},
		{"adjacent URLs", "mirrors=https://one.test/a,https://user:password@two.test/b", "mirrors=[redacted URL]", nil},
		{"secret scheme", "https://user:password@host/a", "[redacted]", []string{"https://"}},
		{"secret across URL", "prefix https://u:p@host/a tail", "[redacted] tail", []string{"prefix https://"}},
		{"secret across URL end", "https://u:p@host/a tail suffix", "[redacted] suffix", []string{"/a tail"}},
		{"URL path secret", "https://u:p@host/private", "[redacted]", []string{"private"}},
		{"opaque URL", "custom://user:password@host/path?key=secret", "custom://host/path", nil},
		{"registered", "Authorization: Bearer secret", "Authorization: Bearer [redacted]", []string{"secret", ""}},
		{"short first", "token-abcdef", "[redacted]", []string{"token-", "token-abcdef"}},
		{"long first", "token-abcdef", "[redacted]", []string{"token-abcdef", "token-"}},
		{"overlap", "abcde", "[redacted]", []string{"abc", "cde"}},
		{"control secret", "prefix a\nb suffix", "prefix [redacted] suffix", []string{"a\nb"}},
		{"unicode", "café /目录", "café /目录", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &Reporter{secrets: tc.secrets}
			if got := r.clean(tc.input); got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestReporter_UntrustedFields(t *testing.T) {
	attack := "secret\n\x1b[2J\u202ehttps://u:p@host/path?token=value"
	var out bytes.Buffer
	cfg := testConfig(&out, false, nil)
	cfg.Secrets = []string{"secret"}
	r := New(t.Context(), cfg)
	for _, err := range []error{
		r.Update(&Phase{Target: attack, Number: 1, Total: 1, Title: attack, Details: attack}),
		r.Warning(attack), r.Fail(Failure{Message: attack, Guidance: attack}),
	} {
		if err != nil {
			t.Fatal(err)
		}
	}
	check := func(text string) {
		t.Helper()
		for _, forbidden := range []string{"secret", "\x1b", "\r", "\u202e", "u:p", "token=value"} {
			if strings.Contains(text, forbidden) {
				t.Fatalf("leaked %q in %q", forbidden, text)
			}
		}
	}
	check(out.String())
	out.Reset()
	r = New(t.Context(), cfg)
	if err := r.Success(&Summary{Target: attack, Image: attack, Platforms: []string{attack},
		Attestations: []string{attack}, Destination: attack}); err != nil {
		t.Fatal(err)
	}
	check(out.String())
}

func TestReporter_InvalidSummaryJoins(t *testing.T) {
	var out bytes.Buffer
	ticks := make(chan time.Time)
	cfg := testConfig(&out, true, nil)
	cfg.Ticks = ticks
	r := New(t.Context(), cfg)
	if err := r.Update(&Phase{Number: 1, Total: 1}); err != nil {
		t.Fatal(err)
	}
	if err := r.Success(&Summary{Layers: -1}); err == nil {
		t.Fatal("accepted negative count")
	}
	select {
	case <-r.done:
	default:
		t.Fatal("Success returned before joining")
	}
	before := out.String()
	close(ticks)
	if err := r.Stop(); err != nil {
		t.Fatal(err)
	}
	if out.String() != before {
		t.Fatal("post-shutdown output")
	}
}
