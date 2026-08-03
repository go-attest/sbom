// Package sbom emits SPDX 2.3 JSON and CycloneDX 1.5 JSON software bills
// of materials for a built pkgx bottle plus its dependency closure.
//
// The package has zero runtime dependencies: documents are built from
// hand-rolled structs and serialized with encoding/json only.
package sbom

import (
	"encoding/json"
	"time"
)

// Component is one package in the bill of materials (a dependency).
type Component struct {
	Name    string
	Version string
	PURL    string // package URL, e.g. "pkg:pkgx/openssl.org@1.1.1w"; optional
	License string // SPDX license expression/id, e.g. "Apache-2.0"; optional
	SHA256  string // lowercase-hex SHA-256 of the component's bottle tarball; optional
}

// Document is a bill of materials whose subject is one built bottle.
type Document struct {
	Name       string      // subject package, e.g. "openssl.org"
	Version    string      // e.g. "1.1.1w"
	PURL       string      // subject package URL; optional
	License    string      // subject license; optional
	SHA256     string      // subject bottle digest; optional
	Namespace  string      // stable document identity URI (SPDX documentNamespace)
	Created    time.Time   // build timestamp (rendered as RFC 3339 UTC)
	Components []Component // dependency closure
}

// marshalIndent is a seam so tests can exercise the marshal error paths.
var marshalIndent = json.MarshalIndent

// noAssertion is the SPDX field value for "no claim is made".
const noAssertion = "NOASSERTION"

// spdxDocument is the top-level SPDX 2.3 JSON shape.
type spdxDocument struct {
	SPDXVersion       string             `json:"spdxVersion"`
	DataLicense       string             `json:"dataLicense"`
	SPDXID            string             `json:"SPDXID"`
	Name              string             `json:"name"`
	DocumentNamespace string             `json:"documentNamespace"`
	CreationInfo      spdxCreationInfo   `json:"creationInfo"`
	Packages          []spdxPackage      `json:"packages"`
	Relationships     []spdxRelationship `json:"relationships"`
}

type spdxCreationInfo struct {
	Created  string   `json:"created"`
	Creators []string `json:"creators"`
}

type spdxPackage struct {
	SPDXID           string            `json:"SPDXID"`
	Name             string            `json:"name"`
	VersionInfo      string            `json:"versionInfo"`
	DownloadLocation string            `json:"downloadLocation"`
	LicenseConcluded string            `json:"licenseConcluded"`
	LicenseDeclared  string            `json:"licenseDeclared"`
	CopyrightText    string            `json:"copyrightText"`
	Checksums        []spdxChecksum    `json:"checksums,omitempty"`
	ExternalRefs     []spdxExternalRef `json:"externalRefs,omitempty"`
}

type spdxChecksum struct {
	Algorithm     string `json:"algorithm"`
	ChecksumValue string `json:"checksumValue"`
}

type spdxExternalRef struct {
	ReferenceCategory string `json:"referenceCategory"`
	ReferenceType     string `json:"referenceType"`
	ReferenceLocator  string `json:"referenceLocator"`
}

type spdxRelationship struct {
	SPDXElementID      string `json:"spdxElementId"`
	RelationshipType   string `json:"relationshipType"`
	RelatedSPDXElement string `json:"relatedSpdxElement"`
}

// sanitizeID maps every non-alphanumeric byte to '-' so the result is a
// valid SPDX identifier fragment.
func sanitizeID(s string) string {
	b := []byte(s)
	for i, c := range b {
		switch {
		case c >= 'a' && c <= 'z':
		case c >= 'A' && c <= 'Z':
		case c >= '0' && c <= '9':
		default:
			b[i] = '-'
		}
	}
	return string(b)
}

// orNoAssertion returns s, or "NOASSERTION" when s is empty.
func orNoAssertion(s string) string {
	if s == "" {
		return noAssertion
	}
	return s
}

// spdxPkg builds one SPDX package entry.
func spdxPkg(id, name, version, license, sha256, purl string) spdxPackage {
	p := spdxPackage{
		SPDXID:           id,
		Name:             name,
		VersionInfo:      version,
		DownloadLocation: noAssertion,
		LicenseConcluded: orNoAssertion(license),
		LicenseDeclared:  orNoAssertion(license),
		CopyrightText:    noAssertion,
	}
	if sha256 != "" {
		p.Checksums = []spdxChecksum{{Algorithm: "SHA256", ChecksumValue: sha256}}
	}
	if purl != "" {
		p.ExternalRefs = []spdxExternalRef{{
			ReferenceCategory: "PACKAGE-MANAGER",
			ReferenceType:     "purl",
			ReferenceLocator:  purl,
		}}
	}
	return p
}

// namespace returns the document namespace, deriving a stable default
// when none was supplied.
func (d Document) namespace() string {
	if d.Namespace != "" {
		return d.Namespace
	}
	return "https://spdx.org/spdxdocs/" + d.Name + "-" + d.Version
}

// SPDX renders the document as indented SPDX 2.3 JSON.
func (d Document) SPDX() ([]byte, error) {
	subjectID := "SPDXRef-Package-" + sanitizeID(d.Name)
	doc := spdxDocument{
		SPDXVersion:       "SPDX-2.3",
		DataLicense:       "CC0-1.0",
		SPDXID:            "SPDXRef-DOCUMENT",
		Name:              d.Name,
		DocumentNamespace: d.namespace(),
		CreationInfo: spdxCreationInfo{
			Created:  d.Created.UTC().Format(time.RFC3339),
			Creators: []string{"Tool: go-attest/sbom"},
		},
		Packages: make([]spdxPackage, 0, 1+len(d.Components)),
		Relationships: make([]spdxRelationship, 0,
			1+len(d.Components)),
	}
	doc.Packages = append(doc.Packages,
		spdxPkg(subjectID, d.Name, d.Version, d.License, d.SHA256, d.PURL))
	doc.Relationships = append(doc.Relationships, spdxRelationship{
		SPDXElementID:      "SPDXRef-DOCUMENT",
		RelationshipType:   "DESCRIBES",
		RelatedSPDXElement: subjectID,
	})
	for i, c := range d.Components {
		id := "SPDXRef-Package-" + sanitizeID(c.Name) + "-" + itoa(i)
		doc.Packages = append(doc.Packages,
			spdxPkg(id, c.Name, c.Version, c.License, c.SHA256, c.PURL))
		doc.Relationships = append(doc.Relationships, spdxRelationship{
			SPDXElementID:      subjectID,
			RelationshipType:   "DEPENDS_ON",
			RelatedSPDXElement: id,
		})
	}
	return marshalIndent(doc, "", "  ")
}

// itoa formats a non-negative int without importing strconv's full surface
// through fmt; it keeps output allocation-light and deterministic.
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var buf [20]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	return string(buf[pos:])
}

// cdxBOM is the top-level CycloneDX 1.5 JSON shape.
type cdxBOM struct {
	BOMFormat   string         `json:"bomFormat"`
	SpecVersion string         `json:"specVersion"`
	Version     int            `json:"version"`
	Metadata    cdxMetadata    `json:"metadata"`
	Components  []cdxComponent `json:"components"`
}

type cdxMetadata struct {
	Timestamp string       `json:"timestamp"`
	Tools     []cdxTool    `json:"tools"`
	Component cdxComponent `json:"component"`
}

type cdxTool struct {
	Vendor string `json:"vendor"`
	Name   string `json:"name"`
}

type cdxComponent struct {
	Type     string             `json:"type"`
	BOMRef   string             `json:"bom-ref"`
	Name     string             `json:"name"`
	Version  string             `json:"version"`
	PURL     string             `json:"purl,omitempty"`
	Licenses []cdxLicenseChoice `json:"licenses,omitempty"`
	Hashes   []cdxHash          `json:"hashes,omitempty"`
}

type cdxLicenseChoice struct {
	License cdxLicense `json:"license"`
}

type cdxLicense struct {
	ID string `json:"id"`
}

type cdxHash struct {
	Alg     string `json:"alg"`
	Content string `json:"content"`
}

// bomRef returns a stable bom-ref: the PURL when present, else name@version.
func bomRef(name, version, purl string) string {
	if purl != "" {
		return purl
	}
	return name + "@" + version
}

// cdxComp builds one CycloneDX component entry.
func cdxComp(typ, name, version, license, sha256, purl string) cdxComponent {
	c := cdxComponent{
		Type:    typ,
		BOMRef:  bomRef(name, version, purl),
		Name:    name,
		Version: version,
		PURL:    purl,
	}
	if license != "" {
		c.Licenses = []cdxLicenseChoice{{License: cdxLicense{ID: license}}}
	}
	if sha256 != "" {
		c.Hashes = []cdxHash{{Alg: "SHA-256", Content: sha256}}
	}
	return c
}

// CycloneDX renders the document as indented CycloneDX 1.5 JSON.
func (d Document) CycloneDX() ([]byte, error) {
	bom := cdxBOM{
		BOMFormat:   "CycloneDX",
		SpecVersion: "1.5",
		Version:     1,
		Metadata: cdxMetadata{
			Timestamp: d.Created.UTC().Format(time.RFC3339),
			Tools:     []cdxTool{{Vendor: "go-pkgx", Name: "sbom"}},
			Component: cdxComp("application",
				d.Name, d.Version, d.License, d.SHA256, d.PURL),
		},
		Components: make([]cdxComponent, 0, len(d.Components)),
	}
	for _, c := range d.Components {
		bom.Components = append(bom.Components,
			cdxComp("library", c.Name, c.Version, c.License, c.SHA256, c.PURL))
	}
	return marshalIndent(bom, "", "  ")
}
