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
		newRecoveryKeyCmd(),
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
// Password, and re-wraps the answers so they stay valid. A configured
// recovery key cannot be re-wrapped without the key itself, so it is cleared
// and the returned flag tells the caller to warn about it.
func applyRecoveryReset(p config.Paths, answers []string, newPassword string) (bool, error) {
	key, err := recovery.OpenVaultKey(p.Recovery, answers)
	if err != nil {
		return false, err
	}
	info, err := vault.Inspect(p.Vault)
	if err != nil {
		return false, err
	}
	v, err := vault.OpenWithKey(p.Vault, key, info.Salt, info.Params)
	if err != nil {
		return false, errors.New("the vault could not be opened with these answers")
	}
	v.Payload.RecordAudit("vault.rekey", "", "password reset via security questions")
	if err := v.Rekey(newPassword, crypto.DefaultParams()); err != nil {
		return false, err
	}
	questions, err := recovery.QuestionsFor(p.Recovery)
	if err != nil {
		return false, err
	}
	if err := recovery.Setup(p.Recovery, questions, answers, v.Key); err != nil {
		return false, err
	}
	keyCleared := recovery.HasKey(p.Recovery)
	if keyCleared {
		if err := recovery.ClearKey(p.Recovery); err != nil {
			return false, err
		}
	}
	return keyCleared, nil
}

// applyRecoveryResetWithKey unlocks the vault with the recovery key, sets a
// new Master Password, and re-wraps the key. The answers cannot be re-wrapped
// without them, so they are cleared; the returned flag tells the caller to
// warn about re-running setup.
func applyRecoveryResetWithKey(p config.Paths, recoveryKey, newPassword string) (bool, error) {
	key, err := recovery.OpenVaultKeyWithRecoveryKey(p.Recovery, recoveryKey)
	if err != nil {
		return false, err
	}
	info, err := vault.Inspect(p.Vault)
	if err != nil {
		return false, err
	}
	v, err := vault.OpenWithKey(p.Vault, key, info.Salt, info.Params)
	if err != nil {
		return false, errors.New("the vault could not be opened with the recovery key")
	}
	_, questionsErr := recovery.QuestionsFor(p.Recovery)
	v.Payload.RecordAudit("vault.rekey", "", "password reset via recovery key")
	if err := v.Rekey(newPassword, crypto.DefaultParams()); err != nil {
		return false, err
	}
	if err := recovery.ClearQuestions(p.Recovery); err != nil {
		return false, err
	}
	if err := recovery.RewrapKey(p.Recovery, recoveryKey, v.Key); err != nil {
		return false, err
	}
	return questionsErr == nil, nil
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
		Short: "Reset a forgotten Master Password with the answers or the recovery key",
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
			questions, questionsErr := recovery.QuestionsFor(p.Recovery)
			hasKey := recovery.HasKey(p.Recovery)
			if questionsErr != nil && !hasKey {
				if errors.Is(questionsErr, recovery.ErrNotConfigured) {
					return errors.New("recovery is not set up (run 'fvault recovery setup' first)")
				}
				return questionsErr
			}

			mode := "answers"
			if questionsErr == nil && hasKey {
				fmt.Println("Reset using:")
				fmt.Println("  1) Security answers (need 2 of 3)")
				fmt.Println("  2) Recovery key")
				line, err := readLine("Choice [1]: ")
				if err != nil {
					return err
				}
				if strings.TrimSpace(line) == "2" {
					mode = "key"
				}
			} else if questionsErr != nil {
				mode = "key"
			}

			bm := backup.New(p, s)
			if _, err := bm.Create(p.Vault, "pre-recovery"); err != nil {
				fmt.Printf("[WARN] Could not create a pre-reset snapshot: %v\n", err)
			}

			if mode == "key" {
				recoveryKey, err := readPassword("Recovery key: ")
				if err != nil {
					return err
				}
				newPassword, err := newPasswordConfirmed()
				if err != nil {
					return err
				}
				questionsCleared, err := applyRecoveryResetWithKey(p, recoveryKey, newPassword)
				if err != nil {
					return err
				}
				res, err := bm.Create(p.Vault, "recovery-reset")
				if err != nil {
					return err
				}
				fmt.Println("[OK] Master Password reset and vault re-encrypted.")
				fmt.Println("[i]  Your recovery key still works with the new password.")
				if questionsCleared {
					fmt.Println("[i]  Security questions were cleared. Run 'fvault recovery setup' again to reconfigure.")
				}
				printBackupResult(res)
				return nil
			}

			for i, q := range questions {
				fmt.Printf("  %d) %s\n", i+1, q)
			}
			fmt.Printf("(at least %d of %d answers must be correct)\n", recovery.AnswerThreshold, len(questions))
			answers, err := promptAnswers(questions)
			if err != nil {
				return err
			}
			newPassword, err := newPasswordConfirmed()
			if err != nil {
				return err
			}
			keyCleared, err := applyRecoveryReset(p, answers, newPassword)
			if err != nil {
				return err
			}
			res, err := bm.Create(p.Vault, "recovery-reset")
			if err != nil {
				return err
			}
			fmt.Println("[OK] Master Password reset and vault re-encrypted.")
			fmt.Println("[i]  Your security questions still work with the new password.")
			if keyCleared {
				fmt.Println("[i]  Recovery key was cleared (it cannot be re-wrapped without the key). Run 'fvault recovery key' to make a new one.")
			}
			printBackupResult(res)
			return nil
		},
	}
}

func newRecoveryKeyCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "key",
		Short: "Generate or replace the recovery key (shown once)",
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
			if recovery.HasKey(p.Recovery) {
				ok, err := confirm("A recovery key already exists. Replace it?", false)
				if err != nil {
					return err
				}
				if !ok {
					fmt.Println("Cancelled.")
					return nil
				}
			}
			key, err := recovery.SetupKey(p.Recovery, v.Key)
			if err != nil {
				return err
			}
			fmt.Println("[OK] Recovery key created. SAVE IT NOW - it is shown only once:")
			fmt.Println()
			fmt.Printf("    %s\n", key)
			fmt.Println()
			fmt.Println("[i]  Use it with 'fvault recovery reset' (choose 'Recovery key').")
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
			questions, questionsErr := recovery.QuestionsFor(p.Recovery)
			hasKey := recovery.HasKey(p.Recovery)
			if questionsErr != nil && !hasKey {
				if errors.Is(questionsErr, recovery.ErrNotConfigured) {
					fmt.Println("Recovery: NOT set up")
					fmt.Println("[i]  Run 'fvault recovery setup' to enable account recovery.")
					return nil
				}
				return questionsErr
			}
			fmt.Println("Recovery file: " + p.Recovery)
			if questionsErr == nil {
				fmt.Println("Security questions: set up (need 2 of 3 answers)")
				for i, q := range questions {
					fmt.Printf("  %d) %s\n", i+1, q)
				}
			} else {
				fmt.Println("Security questions: cleared")
			}
			if hasKey {
				fmt.Println("Recovery key: set up")
			} else {
				fmt.Println("Recovery key: not set up ('fvault recovery key' to create)")
			}
			return nil
		},
	}
}
