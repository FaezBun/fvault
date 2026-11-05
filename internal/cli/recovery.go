package cli

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"fvault/internal/backup"
	"fvault/internal/config"
	"fvault/internal/crypto"
	"fvault/internal/recovery"
	"fvault/internal/vault"
)

func newRecoveryCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "recovery",
		Short: "Set up or use security-question account recovery",
	}
	cmd.AddCommand(
		newRecoverySetupCmd(),
		newRecoveryResetCmd(),
		newRecoveryDisableCmd(),
		newRecoveryStatusCmd(),
	)
	return cmd
}

// pickQuestions shows the fixed list and reads three distinct numbers.
func pickQuestions() ([]string, error) {
	fmt.Println("Pick 3 security questions (three numbers separated by spaces):")
	for i, q := range recovery.Questions {
		fmt.Printf("  %2d) %s\n", i+1, q)
	}
	for {
		line, err := readLine("Numbers: ")
		if err != nil {
			return nil, err
		}
		fields := strings.Fields(line)
		if len(fields) != 3 {
			fmt.Println("Enter exactly three numbers.")
			continue
		}
		seen := map[int]bool{}
		picks := make([]string, 0, 3)
		valid := true
		for _, f := range fields {
			n, err := strconv.Atoi(f)
			if err != nil || n < 1 || n > len(recovery.Questions) || seen[n] {
				fmt.Printf("Use three different numbers between 1 and %d.\n", len(recovery.Questions))
				valid = false
				break
			}
			seen[n] = true
			picks = append(picks, recovery.Questions[n-1])
		}
		if valid {
			return picks, nil
		}
	}
}

// promptAnswers asks for an answer to every question, twice each.
func promptAnswers(questions []string) ([]string, error) {
	answers := make([]string, 0, len(questions))
	for i, q := range questions {
		for {
			first, err := readPassword(fmt.Sprintf("Answer %d (%s): ", i+1, q))
			if err != nil {
				return nil, err
			}
			if len(recovery.NormalizeAnswer(first)) < recovery.MinAnswerLen {
				fmt.Printf("Answer must be at least %d characters.\n", recovery.MinAnswerLen)
				continue
			}
			second, err := readPassword("Repeat answer: ")
			if err != nil {
				return nil, err
			}
			if recovery.NormalizeAnswer(first) != recovery.NormalizeAnswer(second) {
				fmt.Println("Answers do not match. Try again.")
				continue
			}
			answers = append(answers, first)
			break
		}
	}
	return answers, nil
}

// applyRecoverySetup wraps the vault key under the answers.
func applyRecoverySetup(p config.Paths, questions, answers []string, v *vault.Vault) error {
	return recovery.Setup(p.Recovery, questions, answers, v.Key)
}

// applyRecoveryReset unlocks the vault with the answers, sets a new Master
// Password, and re-wraps the recovery blob so the questions stay valid.
func applyRecoveryReset(p config.Paths, answers []string, newPassword string) error {
	key, err := recovery.OpenVaultKey(p.Recovery, answers)
	if err != nil {
		return err
	}
	info, err := vault.Inspect(p.Vault)
	if err != nil {
		return err
	}
	v, err := vault.OpenWithKey(p.Vault, key, info.Salt, info.Params)
	if err != nil {
		return errors.New("the vault could not be opened with these answers")
	}
	v.Payload.RecordAudit("vault.rekey", "", "password reset via security questions")
	if err := v.Rekey(newPassword, crypto.DefaultParams()); err != nil {
		return err
	}
	questions, err := recovery.QuestionsFor(p.Recovery)
	if err != nil {
		return err
	}
	return recovery.Setup(p.Recovery, questions, answers, v.Key)
}

// offerRecoverySetup runs the mandatory security-question setup right after a
// new vault is created. There is no way to skip it during first run; if the
// input is not interactive the setup is skipped with a warning and can be
// done later with `fvault recovery setup`.
func offerRecoverySetup(p config.Paths, v *vault.Vault) {
	fmt.Println("\nAccount recovery (required):")
	fmt.Println("Answer 3 questions so you can reset a forgotten Master Password.")
	questions, err := pickQuestions()
	if err != nil {
		fmt.Printf("[WARN] Recovery setup skipped: %v. Run 'fvault recovery setup' when you can.\n", err)
		return
	}
	answers, err := promptAnswers(questions)
	if err != nil {
		fmt.Printf("[WARN] Recovery setup skipped: %v. Run 'fvault recovery setup' when you can.\n", err)
		return
	}
	if err := applyRecoverySetup(p, questions, answers, v); err != nil {
		fmt.Printf("[WARN] Could not save security questions: %v\n", err)
		return
	}
	fmt.Println("[OK] Security questions saved. Reset later with 'fvault recovery reset'.")
}

func newRecoverySetupCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "setup",
		Short: "Set or replace the 3 security questions",
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
			if recovery.Configured(p.Recovery) {
				ok, err := confirm("Security questions already exist. Replace them?", false)
				if err != nil {
					return err
				}
				if !ok {
					fmt.Println("Cancelled.")
					return nil
				}
			}
			questions, err := pickQuestions()
			if err != nil {
				return err
			}
			answers, err := promptAnswers(questions)
			if err != nil {
				return err
			}
			if err := applyRecoverySetup(p, questions, answers, v); err != nil {
				return err
			}
			fmt.Println("[OK] Security questions saved to " + p.Recovery)
			return nil
		},
	}
}

func newRecoveryResetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "reset",
		Short: "Reset a forgotten Master Password with the security answers",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			p, err := resolvePaths()
			if err != nil {
				return err
			}
			s, err := loadSettings(p)
			if err != nil {
				return err
			}
			questions, err := recovery.QuestionsFor(p.Recovery)
			if err != nil {
				if errors.Is(err, recovery.ErrNotConfigured) {
					return errors.New("security questions are not set up (run 'fvault recovery setup' first)")
				}
				return err
			}
			for i, q := range questions {
				fmt.Printf("  %d) %s\n", i+1, q)
			}
			answers, err := promptAnswers(questions)
			if err != nil {
				return err
			}
			bm := backup.New(p, s)
			if _, err := bm.Create(p.Vault, "pre-recovery"); err != nil {
				fmt.Printf("[WARN] Could not create a pre-reset snapshot: %v\n", err)
			}
			newPassword, err := newPasswordConfirmed()
			if err != nil {
				return err
			}
			if err := applyRecoveryReset(p, answers, newPassword); err != nil {
				return err
			}
			res, err := bm.Create(p.Vault, "recovery-reset")
			if err != nil {
				return err
			}
			fmt.Println("[OK] Master Password reset and vault re-encrypted.")
			fmt.Println("[i]  Your security questions still work with the new password.")
			printBackupResult(res)
			return nil
		},
	}
}

func newRecoveryDisableCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "disable",
		Short: "Remove the security questions",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			p, err := resolvePaths()
			if err != nil {
				return err
			}
			if !recovery.Configured(p.Recovery) {
				return errors.New("security questions are not configured")
			}
			ok, err := confirm("Remove the security questions?", false)
			if err != nil {
				return err
			}
			if !ok {
				fmt.Println("Cancelled.")
				return nil
			}
			if err := recovery.Remove(p.Recovery); err != nil {
				return err
			}
			fmt.Println("[OK] Security questions removed.")
			return nil
		},
	}
}

func newRecoveryStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show whether security questions are configured",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			p, err := resolvePaths()
			if err != nil {
				return err
			}
			questions, err := recovery.QuestionsFor(p.Recovery)
			if err != nil {
				if errors.Is(err, recovery.ErrNotConfigured) {
					fmt.Println("Security questions: NOT set up")
					fmt.Println("[i]  Run 'fvault recovery setup' to enable account recovery.")
					return nil
				}
				return err
			}
			fmt.Println("Security questions: set up (" + p.Recovery + ")")
			for i, q := range questions {
				fmt.Printf("  %d) %s\n", i+1, q)
			}
			return nil
		},
	}
}
