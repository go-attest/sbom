package sbom

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	spdxjson "github.com/spdx/tools-golang/json"
)

// testDoc covers every optional field both present (subject, first
// component) and absent (second component), plus an empty Namespace so
// the derived default path runs.
func testDoc() Document {
	return Document{
		Name:    "openssl.org",
		Version: "1.1.1w",
		PURL:    "pkg:pkgx/openssl.org@1.1.1w",
		License: "Apache-2.0",
		SHA256:  strings.Repeat("ab", 32),
		Created: time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC),
		Components: []Component{
			{
				Name:    "ca-certs",
				Version: "2024.7.2",
				PURL:    "pkg:pkgx/curl.se/ca-certs@2024.7.2",
				License: "MPL-2.0",
				SHA256:  strings.Repeat("cd", 32),
			},
			{Name: "zlib.net", Version: "1.3.1"},
		},
	}
}

func mustSPDX(t *testing.T, d Document) []byte {
	t.Helper()
	b, err := d.SPDX()
	if err != nil {
		t.Fatalf("SPDX() error: %v", err)
	}
	return b
}

func mustCDX(t *testing.T, d Document) []byte {
	t.Helper()
	b, err := d.CycloneDX()
	if err != nil {
		t.Fatalf("CycloneDX() error: %v", err)
	}
	return b
}

func TestSPDXShape(t *testing.T) {
	b := mustSPDX(t, testDoc())
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	for k, want := range map[string]string{
		"spdxVersion":       "SPDX-2.3",
		"dataLicense":       "CC0-1.0",
		"SPDXID":            "SPDXRef-DOCUMENT",
		"name":              "openssl.org",
		"documentNamespace": "https://spdx.org/spdxdocs/openssl.org-1.1.1w",
	} {
		if got := m[k]; got != want {
			t.Errorf("%s = %v, want %q", k, got, want)
		}
	}
	ci := m["creationInfo"].(map[string]any)
	if got := ci["created"]; got != "2026-08-03T12:00:00Z" {
		t.Errorf("created = %v", got)
	}
	creators := ci["creators"].([]any)
	if len(creators) != 1 || creators[0] != "Tool: go-pkgx/sbom" {
		t.Errorf("creators = %v", creators)
	}

	pkgs := m["packages"].([]any)
	if len(pkgs) != 3 {
		t.Fatalf("packages = %d, want 3", len(pkgs))
	}
	subject := pkgs[0].(map[string]any)
	if got := subject["SPDXID"]; got != "SPDXRef-Package-openssl-org" {
		t.Errorf("subject SPDXID = %v (sanitization)", got)
	}
	if got := subject["licenseConcluded"]; got != "Apache-2.0" {
		t.Errorf("subject licenseConcluded = %v", got)
	}
	if subject["downloadLocation"] != "NOASSERTION" ||
		subject["copyrightText"] != "NOASSERTION" {
		t.Errorf("subject NOASSERTION fields wrong: %v", subject)
	}
	sums := subject["checksums"].([]any)[0].(map[string]any)
	if sums["algorithm"] != "SHA256" ||
		sums["checksumValue"] != strings.Repeat("ab", 32) {
		t.Errorf("subject checksums = %v", sums)
	}
	ref := subject["externalRefs"].([]any)[0].(map[string]any)
	if ref["referenceCategory"] != "PACKAGE-MANAGER" ||
		ref["referenceType"] != "purl" ||
		ref["referenceLocator"] != "pkg:pkgx/openssl.org@1.1.1w" {
		t.Errorf("subject externalRefs = %v", ref)
	}

	full := pkgs[1].(map[string]any)
	if got := full["SPDXID"]; got != "SPDXRef-Package-ca-certs-0" {
		t.Errorf("component 0 SPDXID = %v", got)
	}
	bare := pkgs[2].(map[string]any)
	if got := bare["SPDXID"]; got != "SPDXRef-Package-zlib-net-1" {
		t.Errorf("component 1 SPDXID = %v", got)
	}
	if got := bare["licenseConcluded"]; got != "NOASSERTION" {
		t.Errorf("bare licenseConcluded = %v", got)
	}
	if _, ok := bare["checksums"]; ok {
		t.Error("bare component must have no checksums")
	}
	if _, ok := bare["externalRefs"]; ok {
		t.Error("bare component must have no externalRefs")
	}

	rels := m["relationships"].([]any)
	if len(rels) != 3 {
		t.Fatalf("relationships = %d, want 3", len(rels))
	}
	describes := rels[0].(map[string]any)
	if describes["spdxElementId"] != "SPDXRef-DOCUMENT" ||
		describes["relationshipType"] != "DESCRIBES" ||
		describes["relatedSpdxElement"] != "SPDXRef-Package-openssl-org" {
		t.Errorf("DESCRIBES relationship = %v", describes)
	}
	dep := rels[1].(map[string]any)
	if dep["spdxElementId"] != "SPDXRef-Package-openssl-org" ||
		dep["relationshipType"] != "DEPENDS_ON" ||
		dep["relatedSpdxElement"] != "SPDXRef-Package-ca-certs-0" {
		t.Errorf("DEPENDS_ON relationship = %v", dep)
	}
}

func TestSPDXNamespaceExplicit(t *testing.T) {
	d := testDoc()
	d.Namespace = "https://example.com/sbom/openssl-1.1.1w"
	var m map[string]any
	if err := json.Unmarshal(mustSPDX(t, d), &m); err != nil {
		t.Fatal(err)
	}
	if got := m["documentNamespace"]; got != d.Namespace {
		t.Errorf("documentNamespace = %v, want %q", got, d.Namespace)
	}
}

// TestSPDXConformance decodes our output with the reference SPDX parser.
func TestSPDXConformance(t *testing.T) {
	b := mustSPDX(t, testDoc())
	doc, err := spdxjson.Read(bytes.NewReader(b))
	if err != nil {
		t.Fatalf("reference SPDX parser rejected output: %v", err)
	}
	if doc.SPDXVersion != "SPDX-2.3" {
		t.Errorf("SPDXVersion = %q", doc.SPDXVersion)
	}
	if len(doc.Packages) != 3 {
		t.Errorf("reference parser saw %d packages, want 3", len(doc.Packages))
	}
	if len(doc.Relationships) != 3 {
		t.Errorf("reference parser saw %d relationships, want 3",
			len(doc.Relationships))
	}
}

func TestCycloneDXShape(t *testing.T) {
	b := mustCDX(t, testDoc())
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if m["bomFormat"] != "CycloneDX" || m["specVersion"] != "1.5" ||
		m["version"] != float64(1) {
		t.Errorf("top-level fields wrong: %v", m)
	}
	meta := m["metadata"].(map[string]any)
	if meta["timestamp"] != "2026-08-03T12:00:00Z" {
		t.Errorf("timestamp = %v", meta["timestamp"])
	}
	tool := meta["tools"].([]any)[0].(map[string]any)
	if tool["vendor"] != "go-pkgx" || tool["name"] != "sbom" {
		t.Errorf("tools = %v", tool)
	}
	subject := meta["component"].(map[string]any)
	if subject["type"] != "application" ||
		subject["name"] != "openssl.org" ||
		subject["version"] != "1.1.1w" ||
		subject["bom-ref"] != "pkg:pkgx/openssl.org@1.1.1w" ||
		subject["purl"] != "pkg:pkgx/openssl.org@1.1.1w" {
		t.Errorf("subject component = %v", subject)
	}
	lic := subject["licenses"].([]any)[0].(map[string]any)
	if lic["license"].(map[string]any)["id"] != "Apache-2.0" {
		t.Errorf("subject licenses = %v", lic)
	}
	hash := subject["hashes"].([]any)[0].(map[string]any)
	if hash["alg"] != "SHA-256" || hash["content"] != strings.Repeat("ab", 32) {
		t.Errorf("subject hashes = %v", hash)
	}

	comps := m["components"].([]any)
	if len(comps) != 2 {
		t.Fatalf("components = %d, want 2", len(comps))
	}
	full := comps[0].(map[string]any)
	if full["type"] != "library" ||
		full["bom-ref"] != "pkg:pkgx/curl.se/ca-certs@2024.7.2" {
		t.Errorf("component 0 = %v", full)
	}
	bare := comps[1].(map[string]any)
	if bare["bom-ref"] != "zlib.net@1.3.1" {
		t.Errorf("bare bom-ref = %v (want name@version fallback)",
			bare["bom-ref"])
	}
	for _, k := range []string{"purl", "licenses", "hashes"} {
		if _, ok := bare[k]; ok {
			t.Errorf("bare component must have no %s", k)
		}
	}
}

// TestCycloneDXConformance decodes our output with the reference
// CycloneDX decoder.
func TestCycloneDXConformance(t *testing.T) {
	b := mustCDX(t, testDoc())
	bom := new(cdx.BOM)
	err := cdx.NewBOMDecoder(bytes.NewReader(b), cdx.BOMFileFormatJSON).
		Decode(bom)
	if err != nil {
		t.Fatalf("reference CycloneDX decoder rejected output: %v", err)
	}
	if bom.BOMFormat != "CycloneDX" {
		t.Errorf("BOMFormat = %q", bom.BOMFormat)
	}
	if bom.SpecVersion != cdx.SpecVersion1_5 {
		t.Errorf("SpecVersion = %v, want %v", bom.SpecVersion,
			cdx.SpecVersion1_5)
	}
	if bom.Metadata == nil || bom.Metadata.Component == nil ||
		bom.Metadata.Component.Name != "openssl.org" {
		t.Errorf("reference decoder lost the subject: %+v", bom.Metadata)
	}
	if bom.Components == nil || len(*bom.Components) != 2 {
		t.Errorf("reference decoder saw wrong component count: %+v",
			bom.Components)
	}
}

func TestDeterministic(t *testing.T) {
	d := testDoc()
	if !bytes.Equal(mustSPDX(t, d), mustSPDX(t, d)) {
		t.Error("SPDX() is not deterministic")
	}
	if !bytes.Equal(mustCDX(t, d), mustCDX(t, d)) {
		t.Error("CycloneDX() is not deterministic")
	}
}

func TestMarshalError(t *testing.T) {
	orig := marshalIndent
	defer func() { marshalIndent = orig }()
	boom := errors.New("boom")
	marshalIndent = func(any, string, string) ([]byte, error) {
		return nil, boom
	}
	d := testDoc()
	if _, err := d.SPDX(); !errors.Is(err, boom) {
		t.Errorf("SPDX() error = %v, want boom", err)
	}
	if _, err := d.CycloneDX(); !errors.Is(err, boom) {
		t.Errorf("CycloneDX() error = %v, want boom", err)
	}
}

func TestItoa(t *testing.T) {
	for i, want := range map[int]string{0: "0", 7: "7", 42: "42", 123: "123"} {
		if got := itoa(i); got != want {
			t.Errorf("itoa(%d) = %q, want %q", i, got, want)
		}
	}
}

func TestSanitizeID(t *testing.T) {
	if got := sanitizeID("Foo1.bar_baz"); got != "Foo1-bar-baz" {
		t.Errorf("sanitizeID = %q", got)
	}
}
