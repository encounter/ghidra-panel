package ghidra

import (
	"bufio"
	"strings"
)

const (
	PermRead  = iota
	PermWrite = iota
	PermAdmin = iota
)

const (
	PermReadStr  = "READ_ONLY"
	PermWriteStr = "WRITE"
	PermAdminStr = "ADMIN"
)

const AnonAllowedStr = "=ANONYMOUS_ALLOWED"

var PermDisplay = []string{
	PermRead:  "Read",
	PermWrite: "Write",
	PermAdmin: "Admin",
}

// ACL is an in-memory representation of a repo access list.
type ACL struct {
	AnonymousAccess bool
	Users           map[string]int
}

// ReadACL deserializes an ACL from a given scanner stream.
func ReadACL(scn *bufio.Scanner) (acl *ACL, err error) {
	acl = &ACL{
		Users: make(map[string]int),
	}
	for scn.Scan() {
		line := scn.Text()
		if strings.HasPrefix(line, ";") {
			continue
		}
		line = strings.TrimSpace(line)

		if line == AnonAllowedStr {
			acl.AnonymousAccess = true
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		userName := strings.TrimSpace(parts[0])
		roleName := strings.TrimSpace(parts[1])
		perm := PermFromString(roleName)
		if perm == -1 {
			continue
		}
		acl.Users[userName] = perm
	}
	return acl, scn.Err()
}

func PermFromString(s string) int {
	switch s {
	case PermReadStr:
		return PermRead
	case PermWriteStr:
		return PermWrite
	case PermAdminStr:
		return PermAdmin
	default:
		return -1
	}
}
