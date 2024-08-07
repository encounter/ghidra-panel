package web

import (
	"go.mkw.re/ghidra-panel/ghidra"
	"log"
	"net/http"
	"slices"
)

func (s *Server) handleSetUserAccess(wr http.ResponseWriter, req *http.Request) {
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
	repo := req.PostForm.Get("repo")
	user := req.PostForm.Get("user")
	role := req.PostForm.Get("role")

	// Check for missing form data
	if repo == "" || user == "" || role == "" {
		http.Redirect(wr, req, redirectUrl(req, map[string]string{"status": "missing_fields"}), http.StatusSeeOther)
		return
	}

	// Map permission string to integer
	newPerm := ghidra.PermFromString(role)
	if newPerm == -1 {
		http.Error(wr, "Bad request", http.StatusBadRequest)
		return
	}

	// Allow super admins to set permissions for any user
	if !slices.Contains(s.Config.SuperAdmins, ident.ID) {
		// Fetch user state from the database and Ghidra
		result, err := s.fetchUserPermission(req, ident, repo)
		if err != nil {
			log.Println("Failed to get repository user:", err)
			http.Redirect(wr, req, redirectUrl(req, map[string]string{"status": "internal_error"}), http.StatusSeeOther)
			return
		}

		// Don't allow users to change their own permissions
		if user == result.Username {
			http.Redirect(wr, req, redirectUrl(req, map[string]string{"status": "self_access"}), http.StatusSeeOther)
			return
		}

		// Verify the user has admin access to the repository
		if result.Permission != ghidra.Permission_ADMIN {
			http.Error(wr, "Forbidden", http.StatusForbidden)
			return
		}
	}

	// Update the user's permission in Ghidra
	_, err := s.Client.SetUserPermission(req.Context(), &ghidra.SetUserPermissionRequest{
		Username:   user,
		Repository: repo,
		Permission: newPerm,
	})
	if err != nil {
		log.Println("Failed to set user permission:", err)
		http.Redirect(wr, req, redirectUrl(req, map[string]string{"status": "internal_error"}), http.StatusSeeOther)
		return
	}

	http.Redirect(wr, req, redirectUrl(req, map[string]string{"status": "set_access_success", "statusUser": user}), http.StatusSeeOther)
}
