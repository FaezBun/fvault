package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"fvault/internal/vault"
)

func newAuditCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "audit",
		Short: "Report weak, reused, and old passwords",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			p, err := resolvePaths()
			if err != nil {
				return err
			}
			v, err := openVault(p)
			if err != nil {
				return err
			}
			report := v.Payload.HealthReport()
			fmt.Printf("Audited %d entries.\n", report.Total)
			if len(report.Issues) == 0 {
				fmt.Println("[OK] No issues found - every password is strong, unique, and fresh.")
				return nil
			}
			printAuditSection("Weak passwords", report, "weak")
			printAuditSection("Reused passwords", report, "reused")
			printAuditSection("Old passwords (over a year)", report, "old")
			fmt.Printf("\nTotal: %d issues (weak %d, reused %d, old %d)\n",
				len(report.Issues), report.Weak, report.Reused, report.Old)
			return nil
		},
	}
}

func printAuditSection(title string, report vault.HealthReport, reason string) {
	var issues []vault.HealthIssue
	for _, issue := range report.Issues {
		if issue.Reason == reason {
			issues = append(issues, issue)
		}
	}
	if len(issues) == 0 {
		return
	}
	fmt.Printf("\n%s (%d):\n", title, len(issues))
	for _, issue := range issues {
		if issue.Detail != "" {
			fmt.Printf("  %-40s %s\n", issue.Folder+"/"+issue.Name, issue.Detail)
		} else {
			fmt.Printf("  %s\n", issue.Folder+"/"+issue.Name)
		}
	}
}
