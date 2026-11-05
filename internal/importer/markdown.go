package importer

import (
	"bufio"
	"fmt"
	"io"
	"strings"
)

type Entry struct {
	Folder   string
	Name     string
	Username string
	Password string
	URL      string
	Notes    string
	Tags     []string
	Pinned   bool
	Line     int
}

type Warning struct {
	Line    int
	Message string
}

// Parse reads the documented Markdown format:
//
//	## github
//	username: f8un
//	password: secret
//	url: https://github.com
//	notes: main account
//
// Level-2 and deeper headings ("## name") start a new entry. A single "#"
// heading is treated as a document title. Key/value lines may be prefixed with
// "- " or "* ". Unknown lines are reported as warnings.
func Parse(r io.Reader) ([]Entry, []Warning, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	var entries []Entry
	var warnings []Warning
	var current *Entry
	lineNo := 0

	flush := func() {
		if current == nil {
			return
		}
		if current.Password == "" {
			warnings = append(warnings, Warning{
				Line:    current.Line,
				Message: fmt.Sprintf("entry %q has no password and will be skipped", current.Name),
			})
		} else {
			entries = append(entries, *current)
		}
		current = nil
	}

	for scanner.Scan() {
		lineNo++
		raw := scanner.Text()
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "#") {
			level := len(line) - len(strings.TrimLeft(line, "#"))
			flush()
			if level == 1 {
				continue
			}
			name := strings.TrimSpace(strings.TrimLeft(line, "#"))
			if name == "" {
				warnings = append(warnings, Warning{Line: lineNo, Message: "empty heading ignored"})
				continue
			}
			if idx := strings.LastIndex(name, "/"); idx >= 0 {
				name = strings.TrimSpace(name[idx+1:])
			}
			current = &Entry{Name: name, Line: lineNo}
			continue
		}

		line = strings.TrimSpace(strings.TrimLeft(line, "-*"))
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			warnings = append(warnings, Warning{
				Line:    lineNo,
				Message: "unrecognised line (expected key: value)",
			})
			continue
		}
		if current == nil {
			warnings = append(warnings, Warning{
				Line:    lineNo,
				Message: "key/value found before an entry heading; ignored",
			})
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)
		switch key {
		case "username", "user", "login":
			current.Username = value
		case "password", "pass":
			current.Password = value
		case "url", "site", "link":
			current.URL = value
		case "notes", "note":
			current.Notes = value
		default:
			warnings = append(warnings, Warning{
				Line:    lineNo,
				Message: fmt.Sprintf("unknown field %q ignored", key),
			})
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, warnings, err
	}
	flush()
	return entries, warnings, nil
}

// Mask hides most of a password for previews.
func Mask(s string) string {
	if s == "" {
		return ""
	}
	if len(s) <= 4 {
		return strings.Repeat("*", len(s))
	}
	return s[:2] + strings.Repeat("*", len(s)-4) + s[len(s)-2:]
}
