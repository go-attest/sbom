// Command sbom emits an SPDX 2.3 or CycloneDX 1.5 JSON bill of materials
// for a single subject package described by flags.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/go-pkgx/sbom"
)

// osExit and now are seams for tests.
var (
	osExit = os.Exit
	now    = time.Now
)

// generate is a seam so tests can exercise the error path of run.
var generate = func(d sbom.Document, format string) ([]byte, error) {
	if format == "spdx" {
		return d.SPDX()
	}
	return d.CycloneDX()
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("sbom", flag.ContinueOnError)
	fs.SetOutput(stderr)
	format := fs.String("format", "spdx", `output format: "spdx" or "cyclonedx"`)
	name := fs.String("name", "", "subject package name (required)")
	version := fs.String("version", "", "subject package version (required)")
	purl := fs.String("purl", "", "subject package URL")
	license := fs.String("license", "", "subject SPDX license id")
	sha256 := fs.String("sha256", "", "subject bottle SHA-256 (lowercase hex)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *format != "spdx" && *format != "cyclonedx" {
		fmt.Fprintf(stderr, "sbom: unknown format %q\n", *format)
		return 2
	}
	if *name == "" || *version == "" {
		fmt.Fprintln(stderr, "sbom: --name and --version are required")
		return 2
	}
	d := sbom.Document{
		Name:    *name,
		Version: *version,
		PURL:    *purl,
		License: *license,
		SHA256:  *sha256,
		Created: now(),
	}
	b, err := generate(d, *format)
	if err != nil {
		fmt.Fprintln(stderr, "sbom:", err)
		return 1
	}
	fmt.Fprintln(stdout, string(b))
	return 0
}

func main() {
	osExit(run(os.Args[1:], os.Stdout, os.Stderr))
}
