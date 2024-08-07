package web

import (
	"log"
	"net/http"
	"net/url"

	"go.mkw.re/ghidra-panel/common"
)

func (s *Server) handleLogin(wr http.ResponseWriter, req *http.Request) {
	if _, ok := s.checkAuth(req); ok {
		s.redirectHome(wr, req)
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
			log.Println("Failed to serve login:", err)
			_, _ = wr.Write([]byte("Failed to render the login page"))
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
			s.redirectHome(wr, req)
			return
		}
		http.Redirect(wr, req, s.Auth.AuthURL(), http.StatusSeeOther)
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
	s.redirectHome(wr, req)
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
		MaxAge: 0,
	})
	s.redirectLogin(wr, req, false)
}

// redirectHome redirects to the home page or a stored redirect target.
func (s *Server) redirectHome(wr http.ResponseWriter, req *http.Request) {
	if toUrl := fetchRedirect(wr, req); toUrl != nil {
		http.Redirect(wr, req, toUrl.String(), http.StatusSeeOther)
	} else {
		http.Redirect(wr, req, "/", http.StatusSeeOther)
	}
}

// fetchRedirect fetches the redirect URL from the request cookies.
func fetchRedirect(wr http.ResponseWriter, req *http.Request) *url.URL {
	cookie, err := req.Cookie("redirect")
	if err != nil {
		return nil
	}
	// Clear the redirect cookie
	http.SetCookie(wr, &http.Cookie{
		Name:   "redirect",
		Value:  "",
		Path:   "/",
		MaxAge: 0,
	})
	toUrl, err := url.Parse(cookie.Value)
	if err != nil {
		return nil
	}
	return toUrl
}

// redirectLogin redirects to the login page, optionally storing the current URL as a redirect target.
func (s *Server) redirectLogin(wr http.ResponseWriter, req *http.Request, store bool) {
	if store {
		http.SetCookie(wr, &http.Cookie{
			Name:  "redirect",
			Value: req.RequestURI,
			Path:  "/",
		})
	}
	http.Redirect(wr, req, "/login", http.StatusSeeOther)
}
