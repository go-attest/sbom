package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-attest/sbom"
)

func fixedNow() time.Time {
	return time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
}

func runCapture(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	origNow := now
	now = fixedNow
	defer func() { now = origNow }()
	var stdout, stderr bytes.Buffer
	code := run(args, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func TestRunSPDX(t *testing.T) {
	code, out, errOut := runCapture(t,
		"--format", "spdx", "--name", "openssl.org", "--version", "1.1.1w",
		"--purl", "pkg:pkgx/openssl.org@1.1.1w",
		"--license", "Apache-2.0", "--sha256", strings.Repeat("ab", 32))
	if code != 0 {
		t.Fatalf("exit = %d, stderr = %q", code, errOut)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(out), &m); err != nil {
		t.Fatalf("stdout is not JSON: %v", err)
	}
	if m["spdxVersion"] != "SPDX-2.3" {
		t.Errorf("spdxVersion = %v", m["spdxVersion"])
	}
}

func TestRunCycloneDX(t *testing.T) {
	code, out, errOut := runCapture(t,
		"--format", "cyclonedx", "--name", "zlib.net", "--version", "1.3.1")
	if code != 0 {
		t.Fatalf("exit = %d, stderr = %q", code, errOut)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(out), &m); err != nil {
		t.Fatalf("stdout is not JSON: %v", err)
	}
	if m["bomFormat"] != "CycloneDX" || m["specVersion"] != "1.5" {
		t.Errorf("top-level fields wrong: %v", m)
	}
}

func TestRunParseError(t *testing.T) {
	code, _, errOut := runCapture(t, "--no-such-flag")
	if code != 2 {
		t.Errorf("exit = %d, want 2", code)
	}
	if !strings.Contains(errOut, "flag provided but not defined") {
		t.Errorf("stderr = %q", errOut)
	}
}

func TestRunBadFormat(t *testing.T) {
	code, _, errOut := runCapture(t,
		"--format", "xml", "--name", "a", "--version", "1")
	if code != 2 || !strings.Contains(errOut, "unknown format") {
		t.Errorf("exit = %d, stderr = %q", code, errOut)
	}
}

func TestRunMissingName(t *testing.T) {
	code, _, errOut := runCapture(t, "--version", "1")
	if code != 2 || !strings.Contains(errOut, "required") {
		t.Errorf("exit = %d, stderr = %q", code, errOut)
	}
}

func TestRunMissingVersion(t *testing.T) {
	code, _, errOut := runCapture(t, "--name", "a")
	if code != 2 || !strings.Contains(errOut, "required") {
		t.Errorf("exit = %d, stderr = %q", code, errOut)
	}
}

func TestRunGenerateError(t *testing.T) {
	orig := generate
	defer func() { generate = orig }()
	generate = func(sbom.Document, string) ([]byte, error) {
		return nil, errors.New("boom")
	}
	code, _, errOut := runCapture(t, "--name", "a", "--version", "1")
	if code != 1 || !strings.Contains(errOut, "boom") {
		t.Errorf("exit = %d, stderr = %q", code, errOut)
	}
}

func TestMain_(t *testing.T) {
	origExit, origArgs := osExit, os.Args
	defer func() { osExit, os.Args = origExit, origArgs }()
	var got int
	osExit = func(code int) { got = code }
	os.Args = []string{"sbom", "--name", "a", "--version", "1",
		"--format", "cyclonedx"}
	// main writes to real stdout; silence it for the test.
	devnull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer devnull.Close()
	origStdout := os.Stdout
	os.Stdout = devnull
	defer func() { os.Stdout = origStdout }()
	main()
	if got != 0 {
		t.Errorf("main exited %d, want 0", got)
	}
}
