package web

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"go.mkw.re/ghidra-panel/common"
	"go.mkw.re/ghidra-panel/discord"
	"go.mkw.re/ghidra-panel/ghidra"
	"log"
	"net/http"
	"time"
)

var colorForPerm = map[int]int{
	ghidra.PermRead:  0x22bb33,
	ghidra.PermWrite: 0x5bc0de,
	ghidra.PermAdmin: 0xbb2124,
}

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
		log.Println("Failed to get user state: ", err)
		http.Redirect(wr, req, "/?status=internal_error", http.StatusSeeOther)
		return
	}

	// Check if the user already has access to the repository
	if s.ACLs.Get().QueryUserAccess(userState.Username, repo) >= newPerm {
		http.Redirect(wr, req, "/?status=request_redundant", http.StatusSeeOther)
		return
	}

	message := s.writeMessage(ident, userState, repo, newPerm)

	// Send access request message
	ctx := context.TODO()
	payloadBuf, _ := json.Marshal(&message)
	req, err = http.NewRequestWithContext(ctx, http.MethodPost, s.Config.DiscordWebhookURL, bytes.NewReader(payloadBuf))
	if err != nil {
		http.Redirect(wr, req, "/?status=internal_error", http.StatusSeeOther)
		return
	}

	req.Header.Set("content-type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		// TODO properly handle
		http.Redirect(wr, req, "/?status=internal_error", http.StatusSeeOther)
		return
	}
	defer res.Body.Close()

	http.Redirect(wr, req, "/?status=request_success", http.StatusSeeOther)
}

func (s *Server) writeMessage(ident *common.Identity, userState *common.UserState, repo string, perm int) discord.WebhookMessage {
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
		Value:  ghidra.PermDisplay[perm],
		Inline: true,
	}

	ghidraEmbed := discord.Embed{
		Title:       "Access Request",
		Description: fmt.Sprintf("<@%d> has requested access to the following repository.", ident.ID),
		Color:       colorForPerm[perm],
		Author:      embedAuthor,
		Fields:      []discord.EmbedField{usernameField, repositoryField, roleField},
		Timestamp:   time.Now().Format(time.RFC3339),
	}

	return discord.WebhookMessage{
		Username:  s.Config.DiscordApp.Name,
		AvatarURL: fmt.Sprintf("https://cdn.discordapp.com/app-icons/%s/%s.png", s.Config.DiscordApp.ID, s.Config.DiscordApp.Icon),
		Embeds:    []discord.Embed{ghidraEmbed},
	}
}
