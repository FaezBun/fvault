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

func TestParseCSVChromeExport(t *testing.T) {
	input := `name,url,username,password,note
GitHub,https://github.com,octocat,s3cret,work
Router Admin,http://192.168.1.1,admin,p@ss,
`
	entries, _, err := ParseCSV(strings.NewReader(input))
	if err != nil {
		t.Fatalf("ParseCSV: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("entries = %+v", entries)
	}
	if entries[0].Name != "GitHub" || entries[0].Username != "octocat" || entries[0].Password != "s3cret" {
		t.Fatalf("entry 0 = %+v", entries[0])
	}
	if entries[1].URL != "" || entries[1].Password != "p@ss" {
		t.Fatalf("entry 1 = %+v", entries[1])
	}
}

func TestParseCSVChromeSemicolonLocale(t *testing.T) {
	input := `name;url;username;password
GitHub;https://github.com;octocat;s3cret
`
	entries, _, err := ParseCSV(strings.NewReader(input))
	if err != nil {
		t.Fatalf("ParseCSV: %v", err)
	}
	if len(entries) != 1 || entries[0].Name != "GitHub" || entries[0].Password != "s3cret" {
		t.Fatalf("entries = %+v", entries)
	}
}

func TestParseCSVFirefoxExport(t *testing.T) {
	input := `url,username,password,httpRealm,formActionOrigin,guid,timeCreated,timeLastUsed,timePasswordChanged
https://github.com/,octocat,s3cret,,https://github.com,abc-123,0,0,0
https://example.com/,me@example.com,hunter2,,https://example.com,def-456,0,0,0
`
	entries, _, err := ParseCSV(strings.NewReader(input))
	if err != nil {
		t.Fatalf("ParseCSV: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("entries = %+v", entries)
	}
	// No name column: the username becomes the entry name (sanitised).
	if entries[1].Name != "me-example.com" || entries[1].Password != "hunter2" {
		t.Fatalf("entry 1 = %+v", entries[1])
	}
}

func TestParseCSVKeePassXCExport(t *testing.T) {
	input := `Title,Username,Password,URL,Notes
Bank,myuser,bankpass,https://bank.example,important
`
	entries, _, err := ParseCSV(strings.NewReader(input))
	if err != nil {
		t.Fatalf("ParseCSV: %v", err)
	}
	if len(entries) != 1 || entries[0].Name != "Bank" || entries[0].Password != "bankpass" || entries[0].Username != "myuser" {
		t.Fatalf("entries = %+v", entries)
	}
}
