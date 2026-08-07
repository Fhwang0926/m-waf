package main

import (
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/Fhwang0926/m-waf/internal/manager"
)

func TestReadRecoveryPassword(t *testing.T) {
	for _, test := range []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{name: "no newline", input: "correct horse battery staple", want: "correct horse battery staple"},
		{name: "unix newline", input: "correct horse battery staple\n", want: "correct horse battery staple"},
		{name: "windows newline", input: "correct horse battery staple\r\n", want: "correct horse battery staple"},
		{name: "multiple lines", input: "first password\nsecond password\n", wantErr: true},
		{name: "empty", input: "", wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := readRecoveryPassword(strings.NewReader(test.input))
			if (err != nil) != test.wantErr {
				t.Fatalf("unexpected error state: %v", err)
			}
			if got != test.want {
				t.Fatalf("got %q, want %q", got, test.want)
			}
		})
	}
}

func TestRunSystemAdminPasswordResetValidatesBeforeLoadingConfiguration(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	err := runSystemAdminPasswordReset(logger, []string{"--username", "admin", "--password-stdin"}, strings.NewReader("too-short\n"))
	if !errors.Is(err, manager.ErrInvalidRecoveryInput) {
		t.Fatalf("expected recovery input validation error, got %v", err)
	}
}
