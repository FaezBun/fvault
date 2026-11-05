package cli

import (
	"crypto/rand"
	"fmt"
	"math/big"

	"fvault/internal/backup"
	"fvault/internal/config"
	"fvault/internal/vault"
)

const (
	lowerChars  = "abcdefghijkmnopqrstuvwxyz"
	upperChars  = "ABCDEFGHJKLMNPQRSTUVWXYZ"
	digitChars  = "23456789"
	symbolChars = "!@#$%^&*()-_=+[]{}:,.?"
)

func generatePassword(length int) (string, error) {
	if length < 12 {
		length = 12
	}
	sets := []string{lowerChars, upperChars, digitChars, symbolChars}
	all := lowerChars + upperChars + digitChars + symbolChars
	out := make([]byte, 0, length)
	for _, set := range sets {
		ch, err := randomChar(set)
		if err != nil {
			return "", err
		}
		out = append(out, ch)
	}
	for len(out) < length {
		ch, err := randomChar(all)
		if err != nil {
			return "", err
		}
		out = append(out, ch)
	}
	for i := len(out) - 1; i > 0; i-- {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			return "", err
		}
		j := int(n.Int64())
		out[i], out[j] = out[j], out[i]
	}
	return string(out), nil
}

func randomChar(set string) (byte, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(len(set))))
	if err != nil {
		return 0, err
	}
	return set[n.Int64()], nil
}

func commitVault(p config.Paths, s config.Settings, v *vault.Vault, reason string) (backup.CreateResult, error) {
	if err := v.Save(); err != nil {
		return backup.CreateResult{}, err
	}
	bm := backup.New(p, s)
	return bm.Create(v.Path, reason)
}

func printBackupResult(res backup.CreateResult) {
	if res.Path != "" {
		fmt.Printf("[OK] Snapshot: %s\n", res.Path)
	}
	if res.Warning != "" {
		fmt.Printf("[WARN] %s\n", res.Warning)
	}
}
