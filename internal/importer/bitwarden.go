package importer

import (
	"encoding/json"
	"fmt"
	"io"
)

type bitwardenExport struct {
	Folders []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"folders"`
	Items []struct {
		Type     int    `json:"type"`
		Name     string `json:"name"`
		FolderID string `json:"folderId"`
		Login    struct {
			Username string `json:"username"`
			Password string `json:"password"`
		} `json:"login"`
	} `json:"items"`
}

// ParseBitwarden reads an unencrypted Bitwarden JSON export.
func ParseBitwarden(r io.Reader) ([]Entry, []Warning, error) {
	var raw bitwardenExport
	if err := json.NewDecoder(r).Decode(&raw); err != nil {
		return nil, nil, err
	}
	folderNames := map[string]string{}
	for _, folder := range raw.Folders {
		folderNames[folder.ID] = folder.Name
	}
	var entries []Entry
	var warnings []Warning
	for i, item := range raw.Items {
		if item.Type != 1 {
			continue
		}
		if item.Login.Password == "" {
			warnings = append(warnings, Warning{Line: i + 1, Message: fmt.Sprintf("entry %q has no password and will be skipped", item.Name)})
			continue
		}
		folder := ""
		if name, ok := folderNames[item.FolderID]; ok {
			folder = name
		}
		entries = append(entries, Entry{
			Folder:   folder,
			Name:     item.Name,
			Username: item.Login.Username,
			Password: item.Login.Password,
			Line:     i + 1,
		})
	}
	return entries, warnings, nil
}
