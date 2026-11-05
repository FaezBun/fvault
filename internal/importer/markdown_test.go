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

func TestParseSimpleLines(t *testing.T) {
	input := `### T490s BIOS
Supervisor : WFS670303
PC : Nbf303303

Student Portal (Degree) : UiTM@Jasin787
Yonny (depres) : !,'8Yw:4m"kg2:'
Foo : pa:ss:word
Huawei mama faezyahizan@gmail : Wfs670303*

Recovery Codes
[[github-recovery-codes.txt]]
`
	entries, warnings, err := Parse(strings.NewReader(input))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	want := map[string]string{
		"Supervisor":                    "WFS670303",
		"PC":                            "Nbf303303",
		"Student-Portal-Degree":         "UiTM@Jasin787",
		"Yonny-depres":                  "!,'8Yw:4m\"kg2:'",
		"Foo":                           "pa:ss:word",
		"Huawei-mama-faezyahizan-gmail": "Wfs670303*",
	}
	if len(entries) != len(want) {
		t.Fatalf("entries = %d (%+v), want %d", len(entries), entries, len(want))
	}
	for _, e := range entries {
		pw, ok := want[e.Name]
		if !ok {
			t.Errorf("unexpected entry %q", e.Name)
			continue
		}
		if e.Password != pw {
			t.Errorf("entry %q password = %q, want %q", e.Name, e.Password, pw)
		}
	}
	// The section heading and text lines must be ignored, not turned into
	// broken entries or hard errors.
	for _, w := range warnings {
		if strings.Contains(w.Message, "T490s") {
			t.Errorf("section heading produced a warning: %s", w.Message)
		}
	}
}

func TestParseClassicStillWorks(t *testing.T) {
	input := `# Title
## github
username: octocat
password: s3cret
unknown: value
`
	entries, warnings, err := Parse(strings.NewReader(input))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(entries) != 1 || entries[0].Name != "github" || entries[0].Password != "s3cret" {
		t.Fatalf("entries = %+v", entries)
	}
	foundUnknown := false
	for _, w := range warnings {
		if strings.Contains(w.Message, `unknown field`) {
			foundUnknown = true
		}
	}
	if !foundUnknown {
		t.Fatalf("expected unknown field warning, got %+v", warnings)
	}
}

func TestSanitizeEntryName(t *testing.T) {
	cases := map[string]string{
		"github":           "github",
		"2016":             "2016",
		"Student Portal":   "Student-Portal",
		"Yonny (depres)":   "Yonny-depres",
		"faezy@gmail.com":  "faezy-gmail.com",
		"-leading":         "leading",
		"  spaced  name  ": "spaced-name",
		"...dots...":       "dots",
	}
	for in, want := range cases {
		if got := sanitizeEntryName(in); got != want {
			t.Errorf("sanitizeEntryName(%q) = %q, want %q", in, got, want)
		}
	}
}
