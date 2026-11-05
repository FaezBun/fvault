package importer

import (
	"encoding/csv"
	"fmt"
	"io"
	"strings"
)

// ParseOnePasswordCSV reads a 1Password CSV export. It looks for Title/Username/
// Password columns and optional Tags.
func ParseOnePasswordCSV(r io.Reader) ([]Entry, []Warning, error) {
	reader := csv.NewReader(r)
	reader.FieldsPerRecord = -1
	rows, err := reader.ReadAll()
	if err != nil {
		return nil, nil, err
	}
	if len(rows) == 0 {
		return nil, nil, fmt.Errorf("CSV file is empty")
	}
	header := map[string]int{}
	for i, name := range rows[0] {
		header[strings.ToLower(strings.TrimSpace(name))] = i
	}
	titleIndex := indexOf(header, "title", "name")
	usernameIndex := indexOf(header, "username", "user", "login")
	passwordIndex := indexOf(header, "password", "pass")
	tagsIndex := indexOf(header, "tags", "tag")
	if titleIndex < 0 {
		return nil, nil, fmt.Errorf("CSV header must contain a title or name column")
	}
	if passwordIndex < 0 {
		return nil, nil, fmt.Errorf("CSV header must contain a password column")
	}

	var entries []Entry
	var warnings []Warning
	for i, row := range rows[1:] {
		if len(row) == 0 || (len(row) == 1 && strings.TrimSpace(row[0]) == "") {
			continue
		}
		name := strings.TrimSpace(rowValue(row, titleIndex))
		if name == "" {
			warnings = append(warnings, Warning{Line: i + 2, Message: "empty name skipped"})
			continue
		}
		password := strings.TrimSpace(rowValue(row, passwordIndex))
		if password == "" {
			warnings = append(warnings, Warning{Line: i + 2, Message: fmt.Sprintf("entry %q has no password and will be skipped", name)})
			continue
		}
		entries = append(entries, Entry{
			Name:     name,
			Username: strings.TrimSpace(rowValue(row, usernameIndex)),
			Password: password,
			Tags:     splitTagField(rowValue(row, tagsIndex)),
			Line:     i + 2,
		})
	}
	return entries, warnings, nil
}

func rowValue(row []string, index int) string {
	if index < 0 || index >= len(row) {
		return ""
	}
	return row[index]
}
