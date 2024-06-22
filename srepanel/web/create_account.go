package web

import (
	"log"
	"net/http"

	"go.mkw.re/ghidra-panel/ghidra"
)

func (s *Server) handleCreateAccount(wr http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(wr, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ident, ok := s.checkAuth(req)
	if !ok {
		http.Error(wr, "Not authorized", http.StatusUnauthorized)
		return
	}

	if err := req.ParseForm(); err != nil {
		http.Error(wr, "Bad request", http.StatusBadRequest)
		return
	}
	user := req.PostForm.Get("username")
	pass := req.PostForm.Get("password")

	// Fallback to the Discord username if no username is provided
	if user == "" {
		user = ident.Username
	}

	// Check for missing form data
	if user == "" || pass == "" {
		http.Redirect(wr, req, "/?status=missing_fields", http.StatusSeeOther)
		return
	}

	exists, err := s.DB.UsernameExists(req.Context(), user)
	if err != nil {
		log.Println("Failed to check if username exists: ", err)
		http.Redirect(wr, req, "/?status=internal_error", http.StatusSeeOther)
		return
	}
	if exists {
		http.Redirect(wr, req, "/?status=username_exists", http.StatusSeeOther)
		return
	}

	// If a legacy Ghidra account exists, make sure the password matches
	hash := s.ACLs.Get().QueryLegacyUser(user)
	if hash != "" && !ghidra.ComparePassword(hash, pass) {
		http.Redirect(wr, req, "/?status=link_failed", http.StatusSeeOther)
		return
	}

	if err := s.DB.CreateAccount(req.Context(), ident.ID, user, pass); err != nil {
		log.Println("Failed to create account for user: ", err)
		http.Redirect(wr, req, "/?status=internal_error", http.StatusSeeOther)
		return
	}

	if hash != "" {
		http.Redirect(wr, req, "/?status=link_success", http.StatusSeeOther)
	} else {
		http.Redirect(wr, req, "/?status=create_account_success", http.StatusSeeOther)
	}
}
