package discord

import (
	"context"
	"encoding/json"
	"errors"
	"golang.org/x/oauth2"
	"net/http"

	"go.mkw.re/ghidra-panel/common"
	"go.mkw.re/ghidra-panel/csrf"
)

func GetApplication(ctx context.Context, botToken string) (*Application, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://discord.com/api/applications/@me", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bot "+botToken)

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	app := Application{}
	if err := json.NewDecoder(res.Body).Decode(&app); err != nil {
		return nil, err
	}

	return &app, nil
}

var Endpoint = oauth2.Endpoint{
	AuthURL:   "https://discord.com/oauth2/authorize",
	TokenURL:  "https://discord.com/api/oauth2/token",
	AuthStyle: oauth2.AuthStyleInParams,
}

type Auth struct {
	oauth2.Config
	prot *csrf.OneTime
}

func NewAuth(clientID, clientSecret, redirectURL string) *Auth {
	config := &Auth{
		Config: oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			Endpoint:     Endpoint,
			RedirectURL:  redirectURL,
			Scopes:       []string{"identify"},
		},
		prot: csrf.NewOneTime(),
	}
	return config
}

func (c *Auth) AuthURL() string {
	return c.Config.AuthCodeURL(c.prot.Issue(), oauth2.AccessTypeOnline)
}

// HandleRedirect handles an OAuth2 redirect from the identity provider.
func (c *Auth) HandleRedirect(wr http.ResponseWriter, req *http.Request) (ident *common.Identity, err error) {
	ctx := req.Context()

	errID := req.FormValue("error")
	errDescription := req.FormValue("error_description")
	if errID != "" {
		if errID == "access_denied" {
			http.Redirect(wr, req, "/login", http.StatusTemporaryRedirect)
			return nil, nil
		}
		http.Error(wr, errDescription, http.StatusUnauthorized)
		return nil, nil
	}

	query := req.URL.Query()
	code := query.Get("code")
	state := query.Get("state")

	// Check CSRF token validity -- do not consume yet
	csrfID, err := c.prot.Check(state)
	if err != nil {
		return nil, err
	}

	// Request authorization token from Discord
	token, err := c.Config.Exchange(ctx, code)
	if err != nil {
		return nil, err
	}

	// Ask Discord for user ID/username associated with token
	ident, err = c.GetDiscordIdentity(ctx, token)
	if err != nil {
		return nil, err
	}

	// Prevent CSRF token reuse
	err = c.prot.Consume(csrfID)
	return
}

func (c *Auth) GetDiscordIdentity(ctx context.Context, token *oauth2.Token) (ident *common.Identity, err error) {
	meReq, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://discord.com/api/oauth2/@me", nil)
	if err != nil {
		return nil, err
	}

	res, err := c.Config.Client(ctx, token).Do(meReq)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	var info struct {
		User struct {
			ID       uint64 `json:"id,string"`
			Username string `json:"username"`
			Avatar   string `json:"avatar"`
		} `json:"user"`
	}
	if err := json.NewDecoder(res.Body).Decode(&info); err != nil {
		return nil, err
	}

	if info.User.ID == 0 || info.User.Username == "" {
		return nil, errors.New("invalid response")
	}

	return &common.Identity{
		ID:         info.User.ID,
		Username:   info.User.Username,
		AvatarHash: info.User.Avatar,
	}, nil
}
