package web

import (
	"go.mkw.re/ghidra-panel/ghidra"
	"log"
	"net/http"
	"net/url"
)

func (s *Server) handleUpdateRepo(wr http.ResponseWriter, req *http.Request) {
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
	webhookUrl := req.PostForm.Get("webhook_url")

	// Check for missing form data.
	if repo == "" {
		http.Redirect(wr, req, redirectUrl(req, map[string]string{"status": "missing_fields"}), http.StatusSeeOther)
		return
	}

	// Verify the user has admin access to the repository
	repoUser, err := s.Client.GetRepositoryUser(req.Context(), &ghidra.GetRepositoryUserRequest{
		Username:   ident.Username,
		Repository: repo,
	})
	if err != nil {
		log.Println("Failed to get repository user:", err)
		http.Redirect(wr, req, redirectUrl(req, map[string]string{"status": "internal_error"}), http.StatusSeeOther)
		return
	}
	if repoUser.Result == nil || repoUser.Result.Permission != ghidra.Permission_ADMIN {
		http.Error(wr, "Forbidden", http.StatusForbidden)
		return
	}

	// Update the repository webhook URL if provided
	if webhookUrl != "" {
		if webhookUrl == "DELETE" {
			webhookUrl = ""
		} else if u, err := url.Parse(webhookUrl); err != nil || u.Scheme == "" || u.Host == "" {
			http.Redirect(wr, req, redirectUrl(req, map[string]string{"status": "bad_webhook_url"}), http.StatusSeeOther)
			return
		}
		if err = s.DB.SetRepositoryWebhook(req.Context(), repo, webhookUrl); err != nil {
			log.Println("Failed to set repository webhook:", err)
			http.Redirect(wr, req, redirectUrl(req, map[string]string{"status": "internal_error"}), http.StatusSeeOther)
			return
		}
	}

	http.Redirect(wr, req, redirectUrl(req, map[string]string{"status": "update_repo_success"}), http.StatusSeeOther)
}
