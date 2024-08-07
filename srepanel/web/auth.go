package web

import (
	"log"
	"net/http"

	"go.mkw.re/ghidra-panel/common"
)

func (s *Server) handleLogin(wr http.ResponseWriter, req *http.Request) {
	_, ok := s.checkAuth(req)
	if ok {
		http.Redirect(wr, req, "/", http.StatusSeeOther)
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
			token, exp := s.Issuer.Issue(ident)
			http.SetCookie(wr, &http.Cookie{
				Name:     "token",
				Value:    token,
				Path:     "/",
				Expires:  exp,
				HttpOnly: true,
				Secure:   true,
			})
			http.Redirect(wr, req, "/", http.StatusSeeOther)
			return
		}
		authURL := s.Auth.AuthURL()
		http.Redirect(wr, req, authURL, http.StatusSeeOther)
	default:
		http.Error(wr, "Method not allowed", http.StatusMethodNotAllowed)
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

	token, exp := s.Issuer.Issue(ident)
	http.SetCookie(wr, &http.Cookie{
		Name:     "token",
		Value:    token,
		Path:     "/",
		Expires:  exp,
		HttpOnly: true,
		Secure:   true,
	})
	http.Redirect(wr, req, "/", http.StatusSeeOther)
}

func (s *Server) checkAuth(req *http.Request) (*common.Identity, bool) {
	cookie, err := req.Cookie("token")
	if err != nil || cookie == nil {
		return nil, false
	}
	ident, err := s.Issuer.Verify(cookie.Value)
	if err != nil {
		// Only log errors in development mode
		if s.Config.Dev {
			log.Print("failed to verify token: ", err)
		}
		return nil, false
	}
	return ident, true
}

func (s *Server) handleLogout(wr http.ResponseWriter, req *http.Request) {
	http.SetCookie(wr, &http.Cookie{
		Name:   "token",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})

	http.Redirect(wr, req, "/login", http.StatusSeeOther)
}
