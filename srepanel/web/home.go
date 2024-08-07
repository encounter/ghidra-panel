package web

import (
	"go.mkw.re/ghidra-panel/common"
	"go.mkw.re/ghidra-panel/ghidra"
	"google.golang.org/protobuf/types/known/emptypb"
	"log"
	"net/http"
	"slices"
	"sort"
	"strings"
)

type HomeState struct {
	*State
	ACL            []common.UserRepoAccessDisplay
	GhidraUsername string
	GhidraVersion  string
	Repos          []string
	SuperAdmin     bool
}

func (s *Server) handleHome(wr http.ResponseWriter, req *http.Request) {
	if req.URL.Path != "/" {
		http.NotFound(wr, req)
		return
	}

	state := HomeState{State: s.stateWithNav(req, Nav{Route: "/", Name: "Ghidra"})}
	if !s.authenticateState(wr, req, state.State) {
		return
	}
	state.SuperAdmin = slices.Contains(s.Config.SuperAdmins, state.Identity.ID)

	// Fetch repository and user information from Ghidra
	reply, err := s.Client.GetRepositoriesAndUsers(req.Context(), &emptypb.Empty{})
	if err != nil {
		log.Println("Failed to fetch repositories:", err)
		s.renderError(wr, http.StatusInternalServerError, "Failed to fetch repositories.", state.State)
		return
	}

	// Store Ghidra version
	state.GhidraVersion = reply.Version.GhidraVersion

	// Check if there's a matching legacy Ghidra account
	for _, u := range reply.Users {
		if strings.EqualFold(u.Username, state.UserState.Username) {
			state.GhidraUsername = u.Username
			break
		}
	}

	// Query for repository access
	state.ACL = make([]common.UserRepoAccessDisplay, 0)
	for _, r := range reply.Repositories {
		acl := common.UserRepoAccessDisplay{
			Repo:    r.Name,
			Perm:    ghidra.Permission_NONE,
			IsAdmin: state.SuperAdmin,
		}
		for _, u := range r.Users {
			if strings.EqualFold(u.User.Username, state.UserState.Username) {
				acl.Perm = u.Permission
				if u.Permission == ghidra.Permission_ADMIN {
					acl.IsAdmin = true
				}
				break
			}
		}
		if acl.IsAdmin || acl.Perm != ghidra.Permission_NONE {
			state.ACL = append(state.ACL, acl)
		}
	}
	sort.Slice(state.ACL, func(i, j int) bool { return lessCaseInsensitive(state.ACL[i].Repo, state.ACL[j].Repo) })

	// Query for repository list
	state.Repos = make([]string, len(reply.Repositories))
	for i, v := range reply.Repositories {
		state.Repos[i] = v.Name
	}
	sort.Slice(state.Repos, func(i, j int) bool { return lessCaseInsensitive(state.Repos[i], state.Repos[j]) })

	err = homePage.Execute(wr, state)
	if err != nil {
		log.Println("Failed to serve home:", err)
		s.renderError(wr, http.StatusInternalServerError, "Failed to render page.", state.State)
	}
}
