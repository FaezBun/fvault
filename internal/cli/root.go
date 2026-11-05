package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"fvault/internal/config"
)

var (
	homeFlag      string
	templatesFlag string
	staticFlag    string
)

func Execute() int {
	root := newRoot()
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		return 1
	}
	return 0
}

func newRoot() *cobra.Command {
	root := &cobra.Command{
		Use:           "fvault",
		Short:         "Encrypted password vault for the CLI and web",
		Version:       "1.1.4",
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runMenu()
		},
	}
	root.PersistentFlags().StringVar(&homeFlag, "home", "", "data directory (default ./data or FVAULT_HOME)")

	root.AddCommand(
		newInitCmd(),
		newStartCmd(),
		newAddCmd(),
		newEditCmd(),
		newImportCSVCommand(),
		newExportCSVCommand(),
		newImportJSONCommand(),
		newExportJSONCommand(),
		newImportBitwardenCommand(),
		newImportOnePasswordCommand(),
		newGetCmd(),
		newListCmd(),
		newSearchCmd(),
		newRemoveCmd(),
		newFolderCmd(),
		newTagCmd(),
		newPasswdCmd(),
		newKitCmd(),
		newRecoveryCmd(),
		newImportCmd(),
		newBackupCmd(),
		newDoctorCmd(),
		newServeCmd(),
		newMenuCmd(),
		newClipboardClearCmd(),
	)
	return root
}

func resolvePaths() (config.Paths, error) {
	home, err := config.ResolveHome(homeFlag)
	if err != nil {
		return config.Paths{}, err
	}
	return config.NewPaths(home), nil
}

func loadSettings(p config.Paths) (config.Settings, error) {
	return config.LoadSettings(p)
}
