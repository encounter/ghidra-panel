package web

import (
	"go.mkw.re/ghidra-panel/common"
	"go.mkw.re/ghidra-panel/ghidra"
	"google.golang.org/protobuf/types/known/emptypb"
	"log"
	"net/http"
	"sort"
)

type RepoState struct {
	*State
	Repo       *common.Repository
	ACL        []common.RepoUserAccessDisplay
	Users      []string
	StatusUser string
	QueryUser  string
	QueryRole  string
}

func (s *Server) handleRepo(wr http.ResponseWriter, req *http.Request) {
	repoName := req.PathValue("repo")
	state := RepoState{
		State: s.stateWithNav(
			req,
			Nav{Route: "/", Name: "Ghidra"},
			Nav{Route: "/repos/" + repoName, Name: repoName},
		),
		StatusUser: req.URL.Query().Get("statusUser"),
		QueryUser:  req.URL.Query().Get("user"),
		QueryRole:  req.URL.Query().Get("role"),
	}
	if !s.authenticateState(wr, req, state.State) {
		return
	}

	// Fetch repository information from the database
	info, err := s.DB.GetRepository(req.Context(), repoName)
	if err != nil {
		log.Println("Failed to fetch repository:", err)
		s.renderError(wr, http.StatusInternalServerError, "Failed to fetch repository.", state.State)
		return
	}
	state.Repo = info

	// Fetch repository and user information from Ghidra
	reply, err := s.Client.GetRepositoriesAndUsers(req.Context(), &emptypb.Empty{})
	if err != nil {
		log.Print("Failed to fetch repositories:", err)
		s.renderError(wr, http.StatusInternalServerError, "Failed to fetch repositories.", state.State)
		return
	}

	// Check if the repository exists
	var repo *ghidra.Repository
	for _, r := range reply.Repositories {
		if r.Name == repoName {
			repo = r
			break
		}
	}
	if repo == nil {
		http.NotFound(wr, req)
		return
	}

	// Ensure current user has admin access to the repository
	var isAdmin bool
	for _, u := range repo.Users {
		if u.User.Username == state.UserState.Username && u.Permission == ghidra.Permission_ADMIN {
			isAdmin = true
			break
		}
	}
	if !isAdmin {
		http.Error(wr, "Not authorized", http.StatusUnauthorized)
		return
	}

	// Query for repository access
	state.ACL = make([]common.RepoUserAccessDisplay, 0)
	for _, u := range repo.Users {
		state.ACL = append(state.ACL, common.RepoUserAccessDisplay{
			User: u.User.Username,
			Perm: u.Permission,
		})
	}
	sort.Slice(state.ACL, func(i, j int) bool { return lessCaseInsensitive(state.ACL[i].User, state.ACL[j].User) })

	// Query for user list
	state.Users = make([]string, len(reply.Users))
	for i, v := range reply.Users {
		state.Users[i] = v.Username
	}
	sort.Slice(state.Users, func(i, j int) bool { return lessCaseInsensitive(state.Users[i], state.Users[j]) })

	err = repoPage.Execute(wr, state)
	if err != nil {
		log.Println("Failed to serve repo:", err)
		s.renderError(wr, http.StatusInternalServerError, "Failed to render page.", state.State)
	}
}
