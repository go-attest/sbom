# sbom

[![ci](https://github.com/go-pkgx/sbom/actions/workflows/ci.yml/badge.svg)](https://github.com/go-pkgx/sbom/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/go-pkgx/sbom.svg)](https://pkg.go.dev/github.com/go-pkgx/sbom)

Pure-Go software bill of materials emitter for built pkgx bottles and
their dependency closures. Emits **SPDX 2.3 JSON** and **CycloneDX 1.5
JSON** with **zero runtime dependencies** — hand-rolled structs plus
`encoding/json` only. Conformance is proven in test-only code by decoding
the output with the reference libraries
([spdx/tools-golang](https://github.com/spdx/tools-golang) and
[CycloneDX/cyclonedx-go](https://github.com/CycloneDX/cyclonedx-go)).

## Usage

```go
import "github.com/go-pkgx/sbom"

d := sbom.Document{
    Name:    "openssl.org",
    Version: "1.1.1w",
    PURL:    "pkg:pkgx/openssl.org@1.1.1w",
    License: "Apache-2.0",
    SHA256:  "…", // lowercase-hex bottle digest
    Created: buildTime,
    Components: []sbom.Component{
        {Name: "ca-certs", Version: "2024.7.2", License: "MPL-2.0"},
    },
}

spdxJSON, _ := d.SPDX()      // indented SPDX 2.3 JSON
cdxJSON, _ := d.CycloneDX()  // indented CycloneDX 1.5 JSON
```

Output is deterministic: the same `Document` always yields byte-identical
bytes. All optional fields (`PURL`, `License`, `SHA256`) are omitted from
the output when empty; SPDX license fields fall back to `NOASSERTION`.

## CLI

```console
$ go run github.com/go-pkgx/sbom/cmd/sbom \
    --format cyclonedx --name openssl.org --version 1.1.1w
```

Flags: `--format spdx|cyclonedx` (default `spdx`), `--name`, `--version`
(both required), and optional `--purl`, `--license`, `--sha256`.

## License

BSD-3-Clause © the sbom authors
