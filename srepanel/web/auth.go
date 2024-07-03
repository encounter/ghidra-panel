package web

import (
	"log"
	"net/http"

	"go.mkw.re/ghidra-panel/common"
)

func (s *Server) handleLogin(wr http.ResponseWriter, req *http.Request) {
	_, ok := s.checkAuth(req)
	if ok {
		http.Redirect(wr, req, "/", http.StatusTemporaryRedirect)
		return
	}

	switch req.Method {
	case http.MethodGet:
		state := s.stateWithNav(
			req,
			Nav{Route: "/", Name: "Ghidra"},
			Nav{Route: "/login", Name: "Login"},
		)
		err := loginPage.Execute(wr, state)
		if err != nil {
			panic(err)
		}
	case http.MethodPost:
		if s.Config.Dev {
			ident := &common.Identity{
				ID:       1,
				Username: "testuser",
			}
			http.SetCookie(wr, &http.Cookie{
				Name:     "token",
				Value:    s.Issuer.Issue(ident),
				Path:     "/",
				HttpOnly: true,
				Secure:   true,
			})
			http.Redirect(wr, req, "/", http.StatusTemporaryRedirect)
			return
		}
		authURL := s.Auth.AuthURL()
		http.Redirect(wr, req, authURL, http.StatusTemporaryRedirect)
	default:
		http.Error(wr, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleOAuthRedirect(wr http.ResponseWriter, req *http.Request) {
	ident, err := s.Auth.HandleRedirect(wr, req)
	if err != nil {
		log.Println("Redirect request failed:", err)
		http.Error(wr, "Authorization failed", http.StatusUnauthorized)
		return
	}
	if ident == nil {
		return
	}

	http.SetCookie(wr, &http.Cookie{
		Name:     "token",
		Value:    s.Issuer.Issue(ident),
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
	})
	http.Redirect(wr, req, "/", http.StatusTemporaryRedirect)
}

func (s *Server) checkAuth(req *http.Request) (*common.Identity, bool) {
	cookie, err := req.Cookie("token")
	if err != nil || cookie == nil {
		return nil, false
	}
	return s.Issuer.Verify(cookie.Value)
}

func (s *Server) handleLogout(wr http.ResponseWriter, req *http.Request) {
	http.SetCookie(wr, &http.Cookie{
		Name:   "token",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})

	http.Redirect(wr, req, "/login", http.StatusTemporaryRedirect)
}
