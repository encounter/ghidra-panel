package common

import "go.mkw.re/ghidra-panel/ghidra"

type Identity struct {
	ID         uint64 `json:"id"`
	Username   string `json:"username"`
	AvatarHash string `json:"avatar"`
}

type GhidraEndpoint struct {
	Hostname string `json:"hostname"`
	Port     uint16 `json:"port"`
}

type UserState struct {
	Username    string
	HasPassword bool
}

type Link struct {
	Name string `json:"name"`
	URL  string `json:"url"`
}

type UserRepoAccessDisplay struct {
	Repo string
	Perm ghidra.Permission
}

type RepoUserAccessDisplay struct {
	User string
	Perm ghidra.Permission
}
