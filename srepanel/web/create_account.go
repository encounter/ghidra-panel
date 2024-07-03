package web

import (
	"go.mkw.re/ghidra-panel/ghidra"
	"log"
	"net/http"
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
		http.Redirect(wr, req, redirectUrl(req, map[string]string{"status": "missing_fields"}), http.StatusSeeOther)
		return
	}

	exists, err := s.DB.UsernameExists(req.Context(), user)
	if err != nil {
		log.Println("Failed to check if username exists:", err)
		http.Redirect(wr, req, redirectUrl(req, map[string]string{"status": "internal_error"}), http.StatusSeeOther)
		return
	}
	if exists {
		http.Redirect(wr, req, redirectUrl(req, map[string]string{"status": "username_exists"}), http.StatusSeeOther)
		return
	}

	// If there's an existing Ghidra account, make sure the password matches
	// The gRPC backend will use case-insensitive matching for the username
	request := ghidra.AuthenticateUserRequest{
		Username: user,
		Password: pass,
	}
	auth, err := s.Client.AuthenticateUser(req.Context(), &request)
	if err != nil {
		log.Println("Failed to authenticate user:", err)
		http.Redirect(wr, req, redirectUrl(req, map[string]string{"status": "internal_error"}), http.StatusSeeOther)
		return
	}
	// If the returned username is empty, the account doesn't exist
	if auth.Username != "" {
		if auth.Success {
			// Use the Ghidra username
			user = auth.Username
		} else {
			http.Redirect(wr, req, redirectUrl(req, map[string]string{"status": "link_failed"}), http.StatusSeeOther)
			return
		}
	}

	// Create the account in the database
	if err := s.DB.CreateAccount(req.Context(), ident.ID, user, pass); err != nil {
		log.Println("Failed to create account for user:", err)
		http.Redirect(wr, req, redirectUrl(req, map[string]string{"status": "internal_error"}), http.StatusSeeOther)
		return
	}

	// Create the account in Ghidra if it doesn't exist
	if auth.Username == "" {
		_, err = s.Client.AddUser(req.Context(), &ghidra.AddUserRequest{Username: user})
		if err != nil {
			log.Println("Failed to create account:", err)
			http.Redirect(wr, req, redirectUrl(req, map[string]string{"status": "internal_error"}), http.StatusSeeOther)
			return
		}
	}

	if auth.Success {
		http.Redirect(wr, req, redirectUrl(req, map[string]string{"status": "link_success"}), http.StatusSeeOther)
	} else {
		http.Redirect(wr, req, redirectUrl(req, map[string]string{"status": "create_account_success"}), http.StatusSeeOther)
	}
}
