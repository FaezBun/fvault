package importer

import (
	"strings"
	"testing"
)

func TestParseCSVSimple(t *testing.T) {
	input := `name,password
Router,secret1
My Router 2.0,secret2
`
	entries, _, err := ParseCSV(strings.NewReader(input))
	if err != nil {
		t.Fatalf("ParseCSV: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("entries = %+v", entries)
	}
	if entries[0].Name != "Router" || entries[0].Password != "secret1" {
		t.Fatalf("entry 0 = %+v", entries[0])
	}
	if entries[1].Name != "My-Router-2.0" {
		t.Fatalf("name not sanitised: %q", entries[1].Name)
	}
}

func TestParseCSVUsernameAsName(t *testing.T) {
	input := `username,password
me@example.com,hunter2
`
	entries, _, err := ParseCSV(strings.NewReader(input))
	if err != nil {
		t.Fatalf("ParseCSV: %v", err)
	}
	if len(entries) != 1 || entries[0].Name != "me-example.com" || entries[0].Username != "me@example.com" {
		t.Fatalf("entries = %+v", entries)
	}
}

func TestParseCSVMissingColumns(t *testing.T) {
	if _, _, err := ParseCSV(strings.NewReader("foo,bar\n1,2\n")); err == nil {
		t.Fatal("expected error for missing name and password columns")
	}
	if _, _, err := ParseCSV(strings.NewReader("name,notes\na,b\n")); err == nil {
		t.Fatal("expected error for missing password column")
	}
}
