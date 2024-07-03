package web

import (
	"embed"
	"html/template"
	"log"
	"net/http"
	"net/url"
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
	repoPage  *template.Template
	errorPage *template.Template
)

func init() {
	templates, err := template.New("").
		Funcs(template.FuncMap{
			"permColor":   ghidra.PermColorHex,
			"permDisplay": ghidra.PermDisplay,
		}).
		ParseFS(templates, "templates/*.gohtml")
	if err != nil {
		panic(err)
	}
	homePage = templates.Lookup("home.gohtml")
	loginPage = templates.Lookup("login.gohtml")
	repoPage = templates.Lookup("repo.gohtml")
	errorPage = templates.Lookup("error.gohtml")
}

type Config struct {
	BaseURL           string
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
	Client ghidra.GhidraClient
}

func NewServer(
	config *Config,
	db *database.DB,
	auth *discord.Auth,
	issuer *token.Issuer,
	client ghidra.GhidraClient,
) (*Server, error) {
	server := &Server{
		Config: config,
		DB:     db,
		Auth:   auth,
		Issuer: issuer,
		Client: client,
	}
	return server, nil
}

func (s *Server) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /", s.handleHome)
	mux.HandleFunc("GET /login", s.handleLogin)
	mux.HandleFunc("POST /login", s.handleLogin)
	mux.HandleFunc("GET /redirect", s.handleOAuthRedirect)
	mux.HandleFunc("GET /logout", s.handleLogout)
	mux.HandleFunc("GET /repos/{repo}", s.handleRepo)

	mux.HandleFunc("POST /create_account", s.handleCreateAccount)
	mux.HandleFunc("POST /update_account", s.handleUpdateAccount)
	mux.HandleFunc("POST /request_access", s.handleRequestAccess)
	mux.HandleFunc("POST /set_user_access", s.handleSetUserAccess)

	// Create file server for assets
	mux.Handle("GET /assets/", http.FileServer(http.FS(assets)))
}

// State holds server-side web page state.
type State struct {
	Identity  *common.Identity // current user, null if unauthenticated
	UserState *common.UserState
	Nav       []Nav         // navigation bar
	Links     []common.Link // footer links
	Ghidra    *common.GhidraEndpoint
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
		http.Redirect(wr, req, "/login", http.StatusUnauthorized)
		return false
	}

	state.Identity = ident

	userState, err := s.DB.GetUserState(req.Context(), ident)
	if err != nil {
		log.Println("Failed to get user state:", err)
		s.renderError(wr, http.StatusInternalServerError, "Failed to get user state.", state)
		return false
	}
	state.UserState = userState

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

// redirectUrl Generates a redirect back to the original resource with added query parameters.
func redirectUrl(req *http.Request, params map[string]string) string {
	out := req.Header.Get("Referer")
	if out == "" {
		out = "/"
	}
	u, err := url.Parse(out)
	if err != nil {
		u, _ = url.Parse("/")
	}
	var q = url.Values{}
	for k, v := range params {
		q.Set(k, v)
	}
	u.RawQuery = q.Encode()
	return u.String()
}
