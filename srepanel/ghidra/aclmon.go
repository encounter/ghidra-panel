package ghidra

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"
)

// ACLMon monitors the ACLs of multiple repos.
type ACLMon struct {
	Dir  string
	ACLs atomic.Pointer[ACLState]
}

// Run starts the ACL monitor main loop.
// Refreshes ACLs every 30 seconds until context is terminated.
// Returns reason for context termination as error.
// TODO upgrade to react to inotify events.
func (a *ACLMon) Run(ctx context.Context) error {
	acls, err := a.updateACLs()
	if err != nil {
		log.Printf("First ACL update failed: %v", err)
	}
	a.ACLs.Store(acls)

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			acls, err := a.updateACLs()
			if err != nil {
				log.Printf("error updating ACLs: %v", err)
				continue
			}
			a.ACLs.Store(acls)
		}
	}
}

func (a *ACLMon) updateACLs() (*ACLState, error) {
	// TODO if only reading one repo fails (e.g. due to perms),
	//      perhaps should not fail entire batch.
	repos, err := DiscoverRepos(a.Dir)
	if err != nil {
		return nil, fmt.Errorf("failed to discover repos: %w", err)
	}
	acls := NewACLState()
	acls.ReadUsers(a.Dir)
	for _, repoPath := range repos {
		if err := acls.AddRepoDir(repoPath); err != nil {
			return nil, fmt.Errorf("failed to add repo: %w", err)
		}
	}
	return acls, nil
}

func (a *ACLMon) Get() *ACLState {
	return a.ACLs.Load()
}

// DiscoverRepos returns a list of directories suspected to be Ghidra repos.
func DiscoverRepos(dir string) ([]string, error) {
	var repos []string
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		if _, err := os.Stat(filepath.Join(dir, entry.Name(), "userAccess.acl")); err != nil {
			continue
		}
		repos = append(repos, filepath.Join(dir, entry.Name()))
	}
	return repos, nil
}

// ACLState indexes all ACLs of a Ghidra instance at a given point in time.
// Immutable object, safe to read concurrently.
type ACLState struct {
	UpdatedAt  time.Time
	Users      Users
	ACLs       map[string]*ACL             // repo => ACL
	AnonAccess []string                    // repos with anon access
	UserAccess map[string][]UserRepoAccess // user => repos
}

// UserRepoAccess represents a user's access to a repo.
type UserRepoAccess struct {
	Repo string
	Perm int
}

func NewACLState() *ACLState {
	return &ACLState{
		UpdatedAt:  time.Now(),
		Users:      make(Users),
		ACLs:       make(map[string]*ACL),
		UserAccess: make(map[string][]UserRepoAccess),
	}
}

// Ghidra repo directory names use _ to denote uppercase letters.
func repoNameFromDir(repoDir string) string {
	base := filepath.Base(repoDir)
	for i := 0; i < len(base); i++ {
		if base[i] == '_' {
			base = base[:i] + string(base[i+1]-32) + base[i+2:]
		}
	}
	return base
}

func (acls *ACLState) AddRepoDir(repoDir string) error {
	repo := repoNameFromDir(repoDir)
	aclPath := filepath.Join(repoDir, "userAccess.acl")
	f, err := os.Open(aclPath)
	if err != nil {
		return fmt.Errorf("failed to open ACL file: %w", err)
	}
	defer f.Close()

	scn := bufio.NewScanner(f)
	acl, err := ReadACL(scn)
	if err != nil {
		return fmt.Errorf("failed to read ACL: %w", err)
	}

	acls.Add(repo, acl)
	return nil
}

func (acls *ACLState) Add(repoName string, a *ACL) {
	acls.ACLs[repoName] = a
	if a.AnonymousAccess {
		acls.AnonAccess = append(acls.AnonAccess, repoName)
	}
	for user, perm := range a.Users {
		acls.UserAccess[user] = append(acls.UserAccess[user], UserRepoAccess{
			Repo: repoName,
			Perm: perm,
		})
	}
}

func (acls *ACLState) QueryUser(user string) []UserRepoAccess {
	if acls == nil {
		return nil
	}
	return acls.UserAccess[user]
}

func (acls *ACLState) QueryUserAccess(user, repo string) int {
	if acls == nil {
		return -1
	}
	for _, access := range acls.UserAccess[user] {
		if access.Repo == repo {
			return access.Perm
		}
	}
	return -1
}

func (acls *ACLState) ReadUsers(dir string) *Users {
	f, err := os.Open(filepath.Join(dir, "users"))
	if err != nil {
		log.Printf("failed to open users file: %v", err)
		return nil
	}
	defer f.Close()

	scn := bufio.NewScanner(f)
	err = ReadUsers(&acls.Users, scn)
	if err != nil {
		log.Printf("failed to read users file: %v", err)
		return nil
	}
	return &acls.Users
}

// QueryLegacyUser returns the legacy Ghidra password hash for a user.
// Returns empty string if user does not exist or has no password.
func (acls *ACLState) QueryLegacyUser(user string) (username string, hash string) {
	if acls == nil {
		return "", ""
	}
	for u, h := range acls.Users {
		if strings.EqualFold(u, user) {
			username = u
			hash = h
			break
		}
	}
	if hash == "" || hash == "*" {
		return "", ""
	}
	return
}

func (acls *ACLState) QueryRepos() []string {
	if acls == nil {
		return nil
	}
	repos := make([]string, 0, len(acls.ACLs))
	for repo := range acls.ACLs {
		repos = append(repos, repo)
	}
	return repos
}
