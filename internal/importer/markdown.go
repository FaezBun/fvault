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

	// hasKeys tracks whether key lines were seen for a pending heading entry.
	hasKeys bool
}

type Warning struct {
	Line    int
	Message string
}

// knownKeys are the field names recognised in the classic key: value format.
// Any other label is treated as a simple "Name : Password" entry.
var knownKeys = map[string]bool{
	"username": true, "user": true, "login": true,
	"password": true, "pass": true,
	"url": true, "site": true, "link": true,
	"notes": true, "note": true,
}

// Parse reads Markdown password files in two formats:
//
// Simple format, one entry per line (recommended):
//
//	Supervisor : WFS670303
//	Student Portal (Degree) : UiTM@Jasin787
//
// Classic format with headings and key lines:
//
//	## github
//	username: f8un
//	password: secret
//
// Level-2 and deeper headings start an entry when key lines follow them; a
// heading that is only a section title (no key lines) is ignored silently.
// A single "#" heading is treated as a document title. Lines may start with an
// optional "- " or "* " prefix.
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
		if !current.hasKeys {
			// Section title only; the entries below it were simple lines.
			current = nil
			return
		}
		if current.Password == "" {
			warnings = append(warnings, Warning{
				Line:    current.Line,
				Message: fmt.Sprintf("entry %q has no password and will be skipped", current.Name),
			})
		} else {
			entries = append(entries, current.entry())
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
		rawLeft, value, ok := strings.Cut(line, ":")
		if !ok {
			warnings = append(warnings, Warning{
				Line:    lineNo,
				Message: "unrecognised line (expected 'Name : Password')",
			})
			continue
		}
		key := strings.ToLower(strings.TrimSpace(rawLeft))
		value = strings.TrimSpace(value)

		switch {
		case knownKeys[key]:
			if current == nil {
				warnings = append(warnings, Warning{
					Line:    lineNo,
					Message: "key/value found before an entry heading; ignored",
				})
				continue
			}
			current.hasKeys = true
			switch key {
			case "username", "user", "login":
				current.Username = value
			case "password", "pass":
				current.Password = value
			case "url", "site", "link":
				current.URL = value
			case "notes", "note":
				current.Notes = value
			}
		case current != nil && current.hasKeys:
			warnings = append(warnings, Warning{
				Line:    lineNo,
				Message: fmt.Sprintf("unknown field %q ignored", key),
			})
		default:
			// Simple "Name : Password" line (possibly under a section title).
			flush()
			name := sanitizeEntryName(strings.TrimSpace(rawLeft))
			if name == "" {
				warnings = append(warnings, Warning{Line: lineNo, Message: "empty entry name skipped"})
				continue
			}
			if value == "" {
				warnings = append(warnings, Warning{
					Line:    lineNo,
					Message: fmt.Sprintf("entry %q has no password and will be skipped", name),
				})
				continue
			}
			entries = append(entries, Entry{Name: name, Password: value, Line: lineNo})
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, warnings, err
	}
	flush()
	return entries, warnings, nil
}

// entry converts a pending heading entry into a value without internal state.
func (e *Entry) entry() Entry {
	return Entry{
		Folder:   e.Folder,
		Name:     e.Name,
		Username: e.Username,
		Password: e.Password,
		URL:      e.URL,
		Notes:    e.Notes,
		Tags:     e.Tags,
		Pinned:   e.Pinned,
		Line:     e.Line,
	}
}

// sanitizeEntryName turns labels like "Student Portal (Degree)" into valid
// vault names such as "Student-Portal-Degree". Valid names are unchanged.
func sanitizeEntryName(s string) string {
	var b strings.Builder
	lastDash := true // suppress a leading separator
	for _, r := range s {
		switch {
		case (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-':
			b.WriteRune(r)
			lastDash = r == '-'
		default:
			if !lastDash {
				b.WriteByte('-')
				lastDash = true
			}
		}
	}
	out := strings.Trim(b.String(), "-._")
	if out == "" {
		return ""
	}
	if len(out) > 63 {
		out = strings.Trim(out[:63], "-._")
	}
	return out
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
