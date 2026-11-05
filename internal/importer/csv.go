package importer

import (
	"encoding/csv"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// ParseCSV reads a CSV file with a header row. It only needs a name column
// (name, title, label, entry or item — or a username column as a fallback) and
// a password column (password or pass). Optional columns: folder, username,
// tags, pinned. Extra columns are ignored.
func ParseCSV(r io.Reader) ([]Entry, []Warning, error) {
	reader := csv.NewReader(r)
	reader.FieldsPerRecord = -1
	rows, err := reader.ReadAll()
	if err != nil {
		return nil, nil, err
	}
	if len(rows) == 0 {
		return nil, nil, fmt.Errorf("CSV file is empty")
	}
	header := make(map[string]int)
	for i, name := range rows[0] {
		header[strings.ToLower(strings.TrimSpace(name))] = i
	}
	nameIndex := indexOf(header, "name", "title", "label", "entry", "item")
	usernameIndex := indexOf(header, "username", "user", "login")
	passwordIndex := indexOf(header, "password", "pass", "pwd")
	if nameIndex < 0 && usernameIndex < 0 {
		return nil, nil, fmt.Errorf("CSV header must contain a name or username column")
	}
	if passwordIndex < 0 {
		return nil, nil, fmt.Errorf("CSV header must contain a password column")
	}

	var entries []Entry
	var warnings []Warning
	for lineNo, row := range rows[1:] {
		if len(row) == 0 || (len(row) == 1 && strings.TrimSpace(row[0]) == "") {
			continue
		}
		name := field(row, header, nameIndex)
		if name == "" {
			name = field(row, header, usernameIndex)
		}
		name = sanitizeEntryName(name)
		if name == "" {
			warnings = append(warnings, Warning{Line: lineNo + 2, Message: "empty name skipped"})
			continue
		}
		entry := Entry{
			Name:     name,
			Line:     lineNo + 2,
			Folder:   field(row, header, indexOf(header, "folder")),
			Username: field(row, header, usernameIndex),
			Password: field(row, header, passwordIndex),
			Tags:     splitTagField(field(row, header, indexOf(header, "tags", "tag"))),
		}
		if pinned, err := strconv.ParseBool(field(row, header, indexOf(header, "pinned", "favorite"))); err == nil {
			entry.Pinned = pinned
		}
		if entry.Password == "" {
			warnings = append(warnings, Warning{Line: entry.Line, Message: fmt.Sprintf("entry %q has no password and will be skipped", entry.Name)})
			continue
		}
		entries = append(entries, entry)
	}
	return entries, warnings, nil
}

func WriteCSV(w io.Writer, entries []Entry) error {
	writer := csv.NewWriter(w)
	if err := writer.Write([]string{"folder", "name", "username", "password", "tags", "pinned"}); err != nil {
		return err
	}
	for _, entry := range entries {
		if err := writer.Write([]string{
			entry.Folder,
			entry.Name,
			entry.Username,
			entry.Password,
			strings.Join(entry.Tags, ";"),
			strconv.FormatBool(entry.Pinned),
		}); err != nil {
			return err
		}
	}
	writer.Flush()
	return writer.Error()
}

func field(row []string, header map[string]int, index int) string {
	if index < 0 || index >= len(row) {
		return ""
	}
	return strings.TrimSpace(row[index])
}

func indexOf(header map[string]int, names ...string) int {
	for _, name := range names {
		if idx, ok := header[name]; ok {
			return idx
		}
	}
	return -1
}

func splitTagField(value string) []string {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	parts := strings.FieldsFunc(value, func(r rune) bool {
		return r == ';' || r == ','
	})
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}
