package provenance

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
	"time"

	itv1 "github.com/in-toto/attestation/go/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

var (
	started  = time.Date(2026, 8, 3, 10, 0, 0, 0, time.UTC)
	finished = time.Date(2026, 8, 3, 10, 5, 30, 0, time.FixedZone("CEST", 2*3600))
)

func fullStatement() Statement {
	return Statement{
		Subjects: []Subject{
			{Name: "openssl.org 1.1.1w linux/x86-64", SHA256: "aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111"},
			{Name: "openssl.org 1.1.1w linux/aarch64", SHA256: "bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222"},
		},
		BuildType:  "https://github.com/go-pkgx/bk/buildtype@v1",
		BuilderID:  "https://github.com/go-pkgx/bk",
		Invocation: "run-12345",
		StartedOn:  started,
		FinishedOn: finished,
		Params: map[string]string{
			"recipe":  "openssl.org",
			"version": "1.1.1w",
			"target":  "linux/x86-64",
		},
		Materials: []Material{
			{URI: "https://github.com/openssl/openssl/archive/OpenSSL_1_1_1w.tar.gz", SHA256: "cccc3333cccc3333cccc3333cccc3333cccc3333cccc3333cccc3333cccc3333"},
			{URI: "https://example.com/no-digest.tar.gz"}, // no SHA256 -> digest omitted
		},
	}
}

func decodeToMap(t *testing.T, b []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return m
}

func TestJSONFull(t *testing.T) {
	b, err := fullStatement().JSON()
	if err != nil {
		t.Fatalf("JSON: %v", err)
	}
	m := decodeToMap(t, b)

	if got := m["_type"]; got != "https://in-toto.io/Statement/v1" {
		t.Errorf("_type = %v", got)
	}
	if got := m["predicateType"]; got != "https://slsa.dev/provenance/v1" {
		t.Errorf("predicateType = %v", got)
	}

	subjects := m["subject"].([]any)
	if len(subjects) != 2 {
		t.Fatalf("subject count = %d, want 2", len(subjects))
	}
	s0 := subjects[0].(map[string]any)
	if got := s0["name"]; got != "openssl.org 1.1.1w linux/x86-64" {
		t.Errorf("subject[0].name = %v", got)
	}
	if got := s0["digest"].(map[string]any)["sha256"]; got != "aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111" {
		t.Errorf("subject[0].digest.sha256 = %v", got)
	}
	s1 := subjects[1].(map[string]any)
	if got := s1["digest"].(map[string]any)["sha256"]; got != "bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222" {
		t.Errorf("subject[1].digest.sha256 = %v", got)
	}

	pred := m["predicate"].(map[string]any)
	bd := pred["buildDefinition"].(map[string]any)
	if got := bd["buildType"]; got != "https://github.com/go-pkgx/bk/buildtype@v1" {
		t.Errorf("buildType = %v", got)
	}
	ep := bd["externalParameters"].(map[string]any)
	if len(ep) != 3 || ep["recipe"] != "openssl.org" || ep["version"] != "1.1.1w" || ep["target"] != "linux/x86-64" {
		t.Errorf("externalParameters = %v", ep)
	}
	ip := bd["internalParameters"].(map[string]any)
	if len(ip) != 0 {
		t.Errorf("internalParameters = %v, want {}", ip)
	}

	deps := bd["resolvedDependencies"].([]any)
	if len(deps) != 2 {
		t.Fatalf("resolvedDependencies count = %d, want 2", len(deps))
	}
	d0 := deps[0].(map[string]any)
	if got := d0["uri"]; got != "https://github.com/openssl/openssl/archive/OpenSSL_1_1_1w.tar.gz" {
		t.Errorf("dep[0].uri = %v", got)
	}
	if got := d0["digest"].(map[string]any)["sha256"]; got != "cccc3333cccc3333cccc3333cccc3333cccc3333cccc3333cccc3333cccc3333" {
		t.Errorf("dep[0].digest.sha256 = %v", got)
	}
	d1 := deps[1].(map[string]any)
	if got := d1["uri"]; got != "https://example.com/no-digest.tar.gz" {
		t.Errorf("dep[1].uri = %v", got)
	}
	if _, present := d1["digest"]; present {
		t.Errorf("dep[1].digest present, want omitted")
	}

	rd := pred["runDetails"].(map[string]any)
	if got := rd["builder"].(map[string]any)["id"]; got != "https://github.com/go-pkgx/bk" {
		t.Errorf("builder.id = %v", got)
	}
	md := rd["metadata"].(map[string]any)
	if got := md["invocationId"]; got != "run-12345" {
		t.Errorf("invocationId = %v", got)
	}
	if got := md["startedOn"]; got != "2026-08-03T10:00:00Z" {
		t.Errorf("startedOn = %v", got)
	}
	// finished is 10:05:30 CEST (+02:00) -> 08:05:30 UTC
	if got := md["finishedOn"]; got != "2026-08-03T08:05:30Z" {
		t.Errorf("finishedOn = %v", got)
	}
}

func TestJSONMinimal(t *testing.T) {
	s := Statement{
		Subjects:   []Subject{{Name: "one", SHA256: "dddd4444dddd4444dddd4444dddd4444dddd4444dddd4444dddd4444dddd4444"}},
		BuildType:  "https://github.com/go-pkgx/bk/buildtype@v1",
		BuilderID:  "https://github.com/go-pkgx/bk",
		StartedOn:  started,
		FinishedOn: started.Add(time.Minute),
		// Params nil, Materials nil, Invocation empty.
	}
	b, err := s.JSON()
	if err != nil {
		t.Fatalf("JSON: %v", err)
	}
	m := decodeToMap(t, b)

	bd := m["predicate"].(map[string]any)["buildDefinition"].(map[string]any)
	ep, ok := bd["externalParameters"].(map[string]any)
	if !ok {
		t.Fatalf("externalParameters missing or not an object: %v", bd["externalParameters"])
	}
	if len(ep) != 0 {
		t.Errorf("externalParameters = %v, want {}", ep)
	}
	if _, present := bd["resolvedDependencies"]; present {
		t.Errorf("resolvedDependencies present, want omitted")
	}

	md := m["predicate"].(map[string]any)["runDetails"].(map[string]any)["metadata"].(map[string]any)
	if _, present := md["invocationId"]; present {
		t.Errorf("invocationId present, want omitted")
	}
	if got := md["startedOn"]; got != "2026-08-03T10:00:00Z" {
		t.Errorf("startedOn = %v", got)
	}
	if got := md["finishedOn"]; got != "2026-08-03T10:01:00Z" {
		t.Errorf("finishedOn = %v", got)
	}
}

func TestJSONDeterministic(t *testing.T) {
	s := fullStatement()
	b1, err := s.JSON()
	if err != nil {
		t.Fatalf("JSON #1: %v", err)
	}
	b2, err := s.JSON()
	if err != nil {
		t.Fatalf("JSON #2: %v", err)
	}
	if !bytes.Equal(b1, b2) {
		t.Errorf("output not byte-identical across calls")
	}
}

func TestJSONMarshalError(t *testing.T) {
	orig := marshalIndent
	defer func() { marshalIndent = orig }()
	wantErr := errors.New("boom")
	marshalIndent = func(v any, prefix, indent string) ([]byte, error) {
		return nil, wantErr
	}
	if _, err := (Statement{}).JSON(); !errors.Is(err, wantErr) {
		t.Errorf("err = %v, want %v", err, wantErr)
	}
}

// TestConformanceInToto decodes our output with the reference in-toto Go
// types (github.com/in-toto/attestation/go/v1, protobuf-generated) via
// protojson, which honors the spec's `_type` JSON field name.
func TestConformanceInToto(t *testing.T) {
	b, err := fullStatement().JSON()
	if err != nil {
		t.Fatalf("JSON: %v", err)
	}

	var st itv1.Statement
	if err := protojson.Unmarshal(b, &st); err != nil {
		t.Fatalf("protojson.Unmarshal into reference v1.Statement: %v", err)
	}

	if got := st.GetType(); got != "https://in-toto.io/Statement/v1" {
		t.Errorf("Type = %q", got)
	}
	if got := st.GetType(); got != itv1.StatementTypeUri {
		t.Errorf("Type = %q, want reference constant %q", got, itv1.StatementTypeUri)
	}
	if got := st.GetPredicateType(); got != "https://slsa.dev/provenance/v1" {
		t.Errorf("PredicateType = %q", got)
	}
	subs := st.GetSubject()
	if len(subs) != 2 {
		t.Fatalf("subject count = %d, want 2", len(subs))
	}
	if got := subs[0].GetDigest()["sha256"]; got != "aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111" {
		t.Errorf("subject[0] sha256 = %q", got)
	}
	if err := st.Validate(); err != nil {
		t.Errorf("reference Validate: %v", err)
	}
}
