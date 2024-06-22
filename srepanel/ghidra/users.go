package ghidra

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"strings"
)

// Users is an in-memory representation of a Ghidra users list.
type Users map[string]string

// ReadUsers deserializes users from a given scanner stream.
func ReadUsers(users *Users, scn *bufio.Scanner) error {
	for scn.Scan() {
		line := scn.Text()
		if strings.HasPrefix(line, ";") {
			continue
		}
		line = strings.TrimSpace(line)

		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 {
			continue
		}
		userName := strings.TrimSpace(parts[0])
		hash := strings.TrimSpace(parts[1])
		(*users)[userName] = hash
	}
	return nil
}

const SaltLen = 4
const Sha256Len = sha256.Size * 2 // base16

// ComparePassword compares a hashed Ghidra password with a plaintext password.
// Ghidra uses a salted SHA-256 hash.
func ComparePassword(hash, password string) bool {
	if len(hash) != SaltLen+Sha256Len {
		return false
	}

	salt := hash[:SaltLen]
	decoded, err := hex.DecodeString(hash[SaltLen:])
	if err != nil {
		return false
	}

	// Hash password with salt
	h := sha256.New()
	h.Write([]byte(salt))
	h.Write([]byte(password))
	return slices.Equal(h.Sum(nil), decoded)
}
