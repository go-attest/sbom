// Package provenance generates SLSA Provenance v1 build attestations
// wrapped in an in-toto Statement v1.
//
// The package is hand-rolled on top of encoding/json and time only; it has
// zero external runtime dependencies. Output is deterministic: two calls to
// JSON on the same Statement return byte-identical bytes.
package provenance

import (
	"encoding/json"
	"time"
)

// StatementType is the in-toto Statement v1 type URI.
const StatementType = "https://in-toto.io/Statement/v1"

// PredicateType is the SLSA Provenance v1 predicate type URI.
const PredicateType = "https://slsa.dev/provenance/v1"

// Subject is an artifact the provenance is about (a built bottle).
type Subject struct {
	Name   string // e.g. "openssl.org 1.1.1w linux/x86-64"
	SHA256 string // lowercase-hex sha256 of the bottle tarball
}

// Material is a resolved input dependency of the build.
type Material struct {
	URI    string // e.g. "https://github.com/openssl/openssl/archive/...tar.gz"
	SHA256 string // optional lowercase-hex digest
}

// Statement describes how one or more bottles were built.
type Statement struct {
	Subjects   []Subject
	BuildType  string            // e.g. "https://github.com/go-pkgx/bk/buildtype@v1"
	BuilderID  string            // e.g. "https://github.com/go-pkgx/bk"
	Invocation string            // build invocation id (e.g. a CI run id); optional
	StartedOn  time.Time         // build start
	FinishedOn time.Time         // build end
	Params     map[string]string // externalParameters (recipe, version, target); optional
	Materials  []Material        // resolvedDependencies; optional
}

// marshalIndent is a seam so the JSON error branch is testable.
var marshalIndent = json.MarshalIndent

// wire types for the in-toto Statement v1 / SLSA Provenance v1 shape.

type wireSubject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

type wireDependency struct {
	URI    string            `json:"uri"`
	Digest map[string]string `json:"digest,omitempty"`
}

type wireBuildDefinition struct {
	BuildType            string            `json:"buildType"`
	ExternalParameters   map[string]string `json:"externalParameters"`
	InternalParameters   map[string]string `json:"internalParameters"`
	ResolvedDependencies []wireDependency  `json:"resolvedDependencies,omitempty"`
}

type wireBuilder struct {
	ID string `json:"id"`
}

type wireMetadata struct {
	InvocationID string `json:"invocationId,omitempty"`
	StartedOn    string `json:"startedOn"`
	FinishedOn   string `json:"finishedOn"`
}

type wireRunDetails struct {
	Builder  wireBuilder  `json:"builder"`
	Metadata wireMetadata `json:"metadata"`
}

type wirePredicate struct {
	BuildDefinition wireBuildDefinition `json:"buildDefinition"`
	RunDetails      wireRunDetails      `json:"runDetails"`
}

type wireStatement struct {
	Type          string        `json:"_type"`
	Subject       []wireSubject `json:"subject"`
	PredicateType string        `json:"predicateType"`
	Predicate     wirePredicate `json:"predicate"`
}

// JSON renders the in-toto Statement v1 wrapping the SLSA Provenance v1
// predicate. The output is deterministic for a given Statement.
func (s Statement) JSON() ([]byte, error) {
	subjects := make([]wireSubject, len(s.Subjects))
	for i, sub := range s.Subjects {
		subjects[i] = wireSubject{
			Name:   sub.Name,
			Digest: map[string]string{"sha256": sub.SHA256},
		}
	}

	params := s.Params
	if params == nil {
		params = map[string]string{}
	}

	var deps []wireDependency
	for _, m := range s.Materials {
		d := wireDependency{URI: m.URI}
		if m.SHA256 != "" {
			d.Digest = map[string]string{"sha256": m.SHA256}
		}
		deps = append(deps, d)
	}

	st := wireStatement{
		Type:          StatementType,
		Subject:       subjects,
		PredicateType: PredicateType,
		Predicate: wirePredicate{
			BuildDefinition: wireBuildDefinition{
				BuildType:            s.BuildType,
				ExternalParameters:   params,
				InternalParameters:   map[string]string{},
				ResolvedDependencies: deps,
			},
			RunDetails: wireRunDetails{
				Builder: wireBuilder{ID: s.BuilderID},
				Metadata: wireMetadata{
					InvocationID: s.Invocation,
					StartedOn:    s.StartedOn.UTC().Format(time.RFC3339),
					FinishedOn:   s.FinishedOn.UTC().Format(time.RFC3339),
				},
			},
		},
	}
	return marshalIndent(st, "", "  ")
}
