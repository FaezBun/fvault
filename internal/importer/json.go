package importer

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

type jsonEntry struct {
	Folder   string   `json:"folder"`
	Name     string   `json:"name"`
	Username string   `json:"username"`
	Password string   `json:"password"`
	Tags     []string `json:"tags"`
	Pinned   bool     `json:"pinned"`
}

// ParseJSON reads a JSON array of entries.
func ParseJSON(r io.Reader) ([]Entry, []Warning, error) {
	var raw []jsonEntry
	if err := json.NewDecoder(r).Decode(&raw); err != nil {
		return nil, nil, err
	}
	var entries []Entry
	var warnings []Warning
	for i, item := range raw {
		if strings.TrimSpace(item.Name) == "" {
			warnings = append(warnings, Warning{Line: i + 1, Message: "empty name skipped"})
			continue
		}
		if item.Password == "" {
			warnings = append(warnings, Warning{Line: i + 1, Message: fmt.Sprintf("entry %q has no password and will be skipped", item.Name)})
			continue
		}
		entries = append(entries, Entry{
			Folder:   item.Folder,
			Name:     item.Name,
			Username: item.Username,
			Password: item.Password,
			Tags:     item.Tags,
			Pinned:   item.Pinned,
			Line:     i + 1,
		})
	}
	return entries, warnings, nil
}

// WriteJSON writes entries as a JSON array.
func WriteJSON(w io.Writer, entries []Entry) error {
	out := make([]jsonEntry, 0, len(entries))
	for _, entry := range entries {
		out = append(out, jsonEntry{
			Folder:   entry.Folder,
			Name:     entry.Name,
			Username: entry.Username,
			Password: entry.Password,
			Tags:     entry.Tags,
			Pinned:   entry.Pinned,
		})
	}
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(out)
}
