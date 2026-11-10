package vault

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"time"
)

// HealthIssue is one finding of the password health audit. It never carries
// the password value itself.
type HealthIssue struct {
	Folder string `json:"folder"`
	Name   string `json:"name"`
	Reason string `json:"reason"` // weak | reused | old
	Detail string `json:"detail,omitempty"`
}

// HealthReport summarises password hygiene across the whole vault.
type HealthReport struct {
	Total  int           `json:"total"`
	Issues []HealthIssue `json:"issues"`
	Weak   int           `json:"weak"`
	Reused int           `json:"reused"`
	Old    int           `json:"old"`
}

// OldPasswordDays flags passwords that have not changed in this many days.
const OldPasswordDays = 365

// weakPasswordBits is the entropy threshold below which a password is
// considered weak.
const weakPasswordBits = 40

var commonPasswords = map[string]bool{
	"password": true, "password1": true, "123456": true, "123456789": true,
	"qwerty": true, "qwerty123": true, "letmein": true, "admin": true,
	"admin123": true, "welcome": true, "monkey": true, "dragon": true,
	"sunshine": true, "princess": true, "football": true, "iloveyou": true,
	"abc123": true, "123123": true, "secret": true, "root": true,
	"changeme": true, "login": true, "master": true, "hunter2": true,
}

// passwordBits estimates entropy from length and character classes.
func passwordBits(pw string) float64 {
	var lower, upper, digit, symbol bool
	for _, r := range pw {
		switch {
		case r >= 'a' && r <= 'z':
			lower = true
		case r >= 'A' && r <= 'Z':
			upper = true
		case r >= '0' && r <= '9':
			digit = true
		default:
			symbol = true
		}
	}
	pool := 0
	if lower {
		pool += 26
	}
	if upper {
		pool += 26
	}
	if digit {
		pool += 10
	}
	if symbol {
		pool += 32
	}
	if pool == 0 {
		return 0
	}
	return float64(len(pw)) * math.Log2(float64(pool))
}

// weakPassword returns a reason when the password is guessable.
func weakPassword(pw string) string {
	if commonPasswords[strings.ToLower(strings.TrimSpace(pw))] {
		return "common password"
	}
	if len(pw) < 8 {
		return "shorter than 8 characters"
	}
	if bits := passwordBits(pw); bits < weakPasswordBits {
		return fmt.Sprintf("low entropy (about %.0f bits)", bits)
	}
	return ""
}

// HealthReport audits every entry for weak, reused, and stale passwords.
func (p *Payload) HealthReport() HealthReport {
	report := HealthReport{}
	type use struct{ folder, name string }
	byPassword := map[string][]use{}

	for _, folder := range p.FolderNames() {
		for name, entry := range p.Folders[folder].Entries {
			report.Total++
			if reason := weakPassword(entry.Password); reason != "" {
				report.Weak++
				report.Issues = append(report.Issues, HealthIssue{
					Folder: folder, Name: name, Reason: "weak", Detail: reason,
				})
			}
			if entry.Password != "" {
				byPassword[entry.Password] = append(byPassword[entry.Password], use{folder, name})
			}
			if t, err := time.Parse(time.RFC3339, entry.UpdatedAt); err == nil {
				if days := int(time.Since(t).Hours() / 24); days > OldPasswordDays {
					report.Old++
					report.Issues = append(report.Issues, HealthIssue{
						Folder: folder, Name: name, Reason: "old",
						Detail: fmt.Sprintf("not changed for %d days", days),
					})
				}
			}
		}
	}

	for _, uses := range byPassword {
		if len(uses) < 2 {
			continue
		}
		for i, u := range uses {
			others := make([]string, 0, len(uses)-1)
			for j, other := range uses {
				if i != j {
					others = append(others, other.folder+"/"+other.name)
				}
			}
			sort.Strings(others)
			report.Reused++
			report.Issues = append(report.Issues, HealthIssue{
				Folder: u.folder, Name: u.name, Reason: "reused",
				Detail: "same password as " + strings.Join(others, ", "),
			})
		}
	}

	sort.Slice(report.Issues, func(i, j int) bool {
		if report.Issues[i].Reason != report.Issues[j].Reason {
			return report.Issues[i].Reason < report.Issues[j].Reason
		}
		if report.Issues[i].Folder != report.Issues[j].Folder {
			return report.Issues[i].Folder < report.Issues[j].Folder
		}
		return report.Issues[i].Name < report.Issues[j].Name
	})
	return report
}
