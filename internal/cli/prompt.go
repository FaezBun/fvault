package cli

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"golang.org/x/term"
)

var stdinReader = bufio.NewReader(os.Stdin)

func readLine(prompt string) (string, error) {
	fmt.Print(prompt)
	line, err := stdinReader.ReadString('\n')
	if err != nil && line == "" {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func promptString(label, defaultValue string) (string, error) {
	suffix := ": "
	if defaultValue != "" {
		suffix = fmt.Sprintf(" [%s]: ", defaultValue)
	}
	value, err := readLine(label + suffix)
	if err != nil && value == "" {
		return "", err
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return defaultValue, nil
	}
	return value, nil
}

func promptRequired(label string) (string, error) {
	for {
		value, err := readLine(label + ": ")
		if err != nil && value == "" {
			return "", err
		}
		value = strings.TrimSpace(value)
		if value != "" {
			return value, nil
		}
		fmt.Println("This value is required.")
	}
}

func readPassword(label string) (string, error) {
	fmt.Print(label)
	if term.IsTerminal(int(os.Stdin.Fd())) {
		b, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		if err != nil {
			return "", err
		}
		return string(b), nil
	}
	line, err := stdinReader.ReadString('\n')
	if err != nil && line == "" {
		return "", err
	}
	fmt.Println()
	return strings.TrimRight(line, "\r\n"), nil
}

func promptPassword(label string) (string, error) {
	p, err := readPassword(label + ": ")
	if err != nil {
		return "", err
	}
	if p == "" {
		return "", errors.New("password cannot be empty")
	}
	return p, nil
}

func confirm(label string, defaultYes bool) (bool, error) {
	suffix := " [y/N]: "
	if defaultYes {
		suffix = " [Y/n]: "
	}
	value, err := readLine(label + suffix)
	if err != nil && value == "" {
		return false, err
	}
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return defaultYes, nil
	}
	return value == "y" || value == "yes", nil
}

func promptInt(label string, defaultValue int) (int, error) {
	value, err := promptString(label, strconv.Itoa(defaultValue))
	if err != nil {
		return 0, err
	}
	n, err := strconv.Atoi(value)
	if err != nil {
		return 0, fmt.Errorf("invalid number %q", value)
	}
	return n, nil
}

func promptNewPassword() (string, error) {
	for {
		first, err := readPassword("Master Password: ")
		if err != nil {
			return "", err
		}
		if len(first) < 8 {
			fmt.Println("Master Password must be at least 8 characters.")
			continue
		}
		second, err := readPassword("Confirm Master Password: ")
		if err != nil {
			return "", err
		}
		if first != second {
			fmt.Println("Passwords do not match. Try again.")
			continue
		}
		if len(first) < 12 {
			fmt.Println("Note: 12+ characters is recommended.")
		}
		return first, nil
	}
}
