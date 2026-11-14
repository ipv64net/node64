package store

import (
	"regexp"
	"testing"
)

func TestExternalUID(t *testing.T) {
	a := ExternalUID(SourceLDAP, "0123abcd")
	if a != ExternalUID(SourceLDAP, "0123abcd") {
		t.Fatal("not deterministic")
	}
	if !regexp.MustCompile(`^[0-9a-f]{32}$`).MatchString(a) {
		t.Fatalf("format: %q", a)
	}
	if a == ExternalUID(SourceOIDC, "0123abcd") || a == ExternalUID(SourceLDAP, "0123abce") {
		t.Fatal("collision between sources/keys")
	}
	// Trenner: ("ab","c") und ("a","bc") verschieden
	if ExternalUID("ab", "c") == ExternalUID("a", "bc") {
		t.Fatal("separator")
	}
}
