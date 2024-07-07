package web

import (
	"bytes"
	"encoding/json"
	"fmt"
	"go.mkw.re/ghidra-panel/common"
	"go.mkw.re/ghidra-panel/discord"
	"go.mkw.re/ghidra-panel/ghidra"
	"log"
	"net/http"
	"net/url"
)

func (s *Server) handleRequestAccess(wr http.ResponseWriter, req *http.Request) {
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
	repo := req.FormValue("repo")
	role := req.FormValue("role")
	if repo == "" || role == "" {
		http.Error(wr, "Bad request", http.StatusBadRequest)
		return
	}

	newPerm := ghidra.PermFromString(role)
	if newPerm == -1 {
		http.Error(wr, "Bad request", http.StatusBadRequest)
		return
	}

	userState, err := s.DB.GetUserState(req.Context(), ident)
	if err != nil {
		log.Println("Failed to get user state:", err)
		http.Redirect(wr, req, redirectUrl(req, map[string]string{"status": "internal_error"}), http.StatusSeeOther)
		return
	}

	// Check if the user already has access to the repository
	reply, err := s.Client.GetRepositoryUser(req.Context(), &ghidra.GetRepositoryUserRequest{
		Username:   userState.Username,
		Repository: repo,
	})
	if err != nil {
		log.Println("Failed to get repository user:", err)
		http.Redirect(wr, req, redirectUrl(req, map[string]string{"status": "internal_error"}), http.StatusSeeOther)
		return
	}
	if reply.Result != nil && reply.Result.Permission >= newPerm {
		http.Redirect(wr, req, redirectUrl(req, map[string]string{"status": "request_redundant"}), http.StatusSeeOther)
		return
	}

	message, err := s.writeMessage(ident, userState, repo, newPerm)
	if err != nil {
		log.Println("Failed to create webhook message:", err)
		http.Redirect(wr, req, redirectUrl(req, map[string]string{"status": "internal_error"}), http.StatusSeeOther)
		return
	}

	// Fetch repository information from the database
	info, err := s.DB.GetRepository(req.Context(), repo)
	if err != nil {
		log.Println("Failed to fetch repository:", err)
		http.Redirect(wr, req, redirectUrl(req, map[string]string{"status": "internal_error"}), http.StatusSeeOther)
		return
	}

	// Send access request message
	webhookUrl := info.WebhookURL
	if webhookUrl == "" {
		// Fallback to the global webhook URL
		webhookUrl = s.Config.DiscordWebhookURL
	}
	payloadBuf, _ := json.Marshal(message)
	req, err = http.NewRequestWithContext(req.Context(), http.MethodPost, webhookUrl, bytes.NewReader(payloadBuf))
	if err != nil {
		log.Println("Failed to create webhook request:", err)
		http.Redirect(wr, req, redirectUrl(req, map[string]string{"status": "internal_error"}), http.StatusSeeOther)
		return
	}

	req.Header.Set("content-type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Println("Failed to send webhook message:", err)
		http.Redirect(wr, req, redirectUrl(req, map[string]string{"status": "internal_error"}), http.StatusSeeOther)
		return
	}
	defer res.Body.Close()

	http.Redirect(wr, req, redirectUrl(req, map[string]string{"status": "request_success"}), http.StatusSeeOther)
}

func (s *Server) writeMessage(ident *common.Identity, userState *common.UserState, repo string, perm ghidra.Permission) (*discord.WebhookMessage, error) {
	embedAuthor := discord.EmbedAuthor{
		Name:    ident.Username,
		IconURL: fmt.Sprintf("https://cdn.discordapp.com/avatars/%d/%s.png", ident.ID, ident.AvatarHash),
	}

	usernameField := discord.EmbedField{
		Name:   "Username",
		Value:  userState.Username,
		Inline: true,
	}

	repositoryField := discord.EmbedField{
		Name:   "Repository",
		Value:  repo,
		Inline: true,
	}

	roleField := discord.EmbedField{
		Name:   "Role",
		Value:  ghidra.PermDisplay(perm),
		Inline: true,
	}

	u, err := url.Parse(s.Config.BaseURL)
	if err != nil {
		log.Println("Failed to parse base URL:", err)
		return nil, err
	}
	u = u.JoinPath("repos", url.PathEscape(repo))
	q := u.Query()
	q.Set("user", userState.Username)
	q.Set("role", ghidra.Permission_name[int32(perm)])
	q.Set("status", "user_prefilled")
	u.RawQuery = q.Encode()
	manageField := discord.EmbedField{
		Name:   "Link",
		Value:  "[Manage repository users](" + u.String() + ")",
		Inline: false,
	}

	ghidraEmbed := discord.Embed{
		Title:       "Access Request",
		Description: fmt.Sprintf("<@%d> has requested access to the following repository.", ident.ID),
		Color:       ghidra.PermColor(perm),
		Author:      embedAuthor,
		Fields:      []discord.EmbedField{usernameField, repositoryField, roleField, manageField},
	}

	return &discord.WebhookMessage{
		Username:  s.Config.DiscordApp.Name,
		AvatarURL: fmt.Sprintf("https://cdn.discordapp.com/app-icons/%s/%s.png", s.Config.DiscordApp.ID, s.Config.DiscordApp.Icon),
		Embeds:    []discord.Embed{ghidraEmbed},
	}, nil
}
