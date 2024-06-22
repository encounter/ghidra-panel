package web

import (
	"log"
	"net/http"
)

func (s *Server) handleUpdateAccount(wr http.ResponseWriter, req *http.Request) {
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
	pass := req.PostForm.Get("password")

	// Check for missing form data.
	if pass == "" {
		http.Redirect(wr, req, "/?status=missing_fields", http.StatusSeeOther)
		return
	}

	if err := s.DB.UpdatePassword(req.Context(), ident.ID, pass); err != nil {
		log.Println("Failed to update account for user: ", err)
		http.Redirect(wr, req, "/?status=internal_error", http.StatusSeeOther)
		return
	}

	http.Redirect(wr, req, "/?status=update_account_success", http.StatusSeeOther)
}
