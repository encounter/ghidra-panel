package web

import (
	"embed"
	"html/template"
	"net/http"
	"sort"
	"unicode"
	"unicode/utf8"

	"go.mkw.re/ghidra-panel/common"
	"go.mkw.re/ghidra-panel/database"
	"go.mkw.re/ghidra-panel/discord"
	"go.mkw.re/ghidra-panel/ghidra"
	"go.mkw.re/ghidra-panel/token"
)

var (
	//go:embed templates/*
	templates embed.FS

	//go:embed assets/*
	assets embed.FS
)

var (
	homePage  *template.Template
	loginPage *template.Template
)

func init() {
	templates, err := template.ParseFS(templates, "templates/*.gohtml")
	if err != nil {
		panic(err)
	}
	homePage = templates.Lookup("home.gohtml")
	loginPage = templates.Lookup("login.gohtml")
}

type Config struct {
	GhidraEndpoint    *common.GhidraEndpoint
	Links             []common.Link
	DiscordApp        *discord.Application
	DiscordWebhookURL string
	Dev               bool // developer mode
}

type Server struct {
	Config *Config
	DB     *database.DB
	Auth   *discord.Auth
	Issuer *token.Issuer
	ACLs   *ghidra.ACLMon
}

func NewServer(
	config *Config,
	db *database.DB,
	auth *discord.Auth,
	issuer *token.Issuer,
	acls *ghidra.ACLMon,
) (*Server, error) {
	server := &Server{
		Config: config,
		DB:     db,
		Auth:   auth,
		Issuer: issuer,
		ACLs:   acls,
	}
	return server, nil
}

func (s *Server) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/", s.handleHome)
	mux.HandleFunc("/login", s.handleLogin)
	mux.HandleFunc("/redirect", s.handleOAuthRedirect)
	mux.HandleFunc("/logout", s.handleLogout)

	mux.HandleFunc("/create_account", s.handleCreateAccount)
	mux.HandleFunc("/update_account", s.handleUpdateAccount)
	mux.HandleFunc("/request_access", s.handleRequestAccess)

	// Create file server for assets
	mux.Handle("/assets/", http.FileServer(http.FS(assets)))
}

// State holds server-side web page state.
type State struct {
	Identity  *common.Identity // current user, null if unauthenticated
	UserState *common.UserState
	Nav       []Nav         // navigation bar
	Links     []common.Link // footer links
	Ghidra    *common.GhidraEndpoint
	ACL       []common.UserRepoAccessDisplay
	Repos     []string
	Status    string
}

type Nav struct {
	Route string
	Name  string
}

func (s *Server) stateWithNav(req *http.Request, nav ...Nav) *State {
	return &State{
		Ghidra: s.Config.GhidraEndpoint,
		Nav:    nav,
		Links:  s.Config.Links,
		Status: req.URL.Query().Get("status"),
	}
}

func (s *Server) authenticateState(wr http.ResponseWriter, req *http.Request, state *State) bool {
	ident, ok := s.checkAuth(req)
	if !ok {
		http.SetCookie(wr, &http.Cookie{
			Name:   "token",
			Value:  "",
			Path:   "/",
			MaxAge: -1,
		})
		http.Redirect(wr, req, "/login", http.StatusTemporaryRedirect)
		return false
	}

	state.Identity = ident

	userState, err := s.DB.GetUserState(req.Context(), ident)
	if err != nil {
		http.Error(wr, "failed to get user state, please contact server admin", http.StatusInternalServerError)
		return false
	}
	state.UserState = userState

	// Check if there's a matching legacy Ghidra account
	if !state.UserState.HasPassword {
		hash := s.ACLs.Get().QueryLegacyUser(state.UserState.Username)
		state.UserState.HasLegacyAccount = hash != ""
	}

	// Query for repository access
	acl := s.ACLs.Get().QueryUser(state.UserState.Username)
	state.ACL = make([]common.UserRepoAccessDisplay, len(acl))
	for i, v := range acl {
		state.ACL[i] = common.UserRepoAccessDisplay{
			Repo: v.Repo,
			Perm: ghidra.PermDisplay[v.Perm],
		}
	}
	sort.Slice(state.ACL, func(i, j int) bool { return lessCaseInsensitive(state.ACL[i].Repo, state.ACL[j].Repo) })

	// Query for repository list
	state.Repos = s.ACLs.Get().QueryRepos()
	sort.Slice(state.Repos, func(i, j int) bool { return lessCaseInsensitive(state.Repos[i], state.Repos[j]) })

	return true
}

// lessCaseInsensitive compares s, t without allocating
func lessCaseInsensitive(s, t string) bool {
	for {
		if len(t) == 0 {
			return false
		}
		if len(s) == 0 {
			return true
		}
		c, sizec := utf8.DecodeRuneInString(s)
		d, sized := utf8.DecodeRuneInString(t)

		lowerc := unicode.ToLower(c)
		lowerd := unicode.ToLower(d)

		if lowerc < lowerd {
			return true
		}
		if lowerc > lowerd {
			return false
		}

		s = s[sizec:]
		t = t[sized:]
	}
}
