package importer

import (
	"strings"
	"testing"
)

func TestParseMarkdown(t *testing.T) {
	input := `# My secrets

## github
username: octocat
password: s3cret
url: https://github.com
notes: personal account

### folder/mail
- user: me@example.com
- pass: hunter2
- site: https://mail.example.com

## nopassword
username: nobody

## aliases
user: alias-user
pass: alias-pass
login: another-user
site: https://example.com
note: aliased fields
unknown: value
`
	entries, warnings, err := Parse(strings.NewReader(input))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("entries = %d, want 3: %+v", len(entries), entries)
	}

	github := entries[0]
	if github.Name != "github" || github.Username != "octocat" || github.Password != "s3cret" {
		t.Fatalf("github = %+v", github)
	}
	if github.URL != "https://github.com" || github.Notes != "personal account" {
		t.Fatalf("github URL/notes = %+v", github)
	}

	mail := entries[1]
	if mail.Name != "mail" || mail.Username != "me@example.com" || mail.Password != "hunter2" {
		t.Fatalf("mail = %+v", mail)
	}

	aliases := entries[2]
	if aliases.Username != "another-user" || aliases.Password != "alias-pass" {
		t.Fatalf("aliases = %+v", aliases)
	}

	if len(warnings) == 0 {
		t.Fatal("expected warnings for the missing password and unknown field")
	}
	foundNoPassword := false
	foundUnknown := false
	for _, w := range warnings {
		if strings.Contains(w.Message, "no password") {
			foundNoPassword = true
		}
		if strings.Contains(w.Message, "unknown field") {
			foundUnknown = true
		}
	}
	if !foundNoPassword || !foundUnknown {
		t.Fatalf("warnings = %+v", warnings)
	}
}

func TestParseWarningsBeforeHeading(t *testing.T) {
	entries, warnings, err := Parse(strings.NewReader("username: orphan\nnot a pair\n"))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("entries = %+v", entries)
	}
	if len(warnings) != 2 {
		t.Fatalf("warnings = %+v", warnings)
	}
}

func TestParseEmpty(t *testing.T) {
	entries, warnings, err := Parse(strings.NewReader(""))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(entries) != 0 || len(warnings) != 0 {
		t.Fatalf("entries=%v warnings=%v", entries, warnings)
	}
}

func TestParseHeadingWithoutName(t *testing.T) {
	_, warnings, err := Parse(strings.NewReader("##\n"))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0].Message, "empty heading") {
		t.Fatalf("warnings = %+v", warnings)
	}
}

func TestMask(t *testing.T) {
	cases := map[string]string{
		"":           "",
		"a":          "*",
		"abcd":       "****",
		"abcdef":     "ab**ef",
		"longsecret": "lo******et",
	}
	for input, want := range cases {
		if got := Mask(input); got != want {
			t.Errorf("Mask(%q) = %q, want %q", input, got, want)
		}
	}
}
