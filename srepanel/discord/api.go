package discord

// --------------- //
// Application API //
// --------------- //

// Application https://discord.com/developers/docs/resources/application#application-object
type Application struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Icon string `json:"icon"`
}

// ----------- //
// Channel API //
// ----------- //

// EmbedAuthor https://discord.com/developers/docs/resources/channel#embed-object-embed-author-structure
type EmbedAuthor struct {
	Name    string `json:"name"`
	IconURL string `json:"icon_url"`
}

// EmbedField https://discord.com/developers/docs/resources/channel#embed-object-embed-field-structure
type EmbedField struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Inline bool   `json:"inline"`
}

// Embed https://discord.com/developers/docs/resources/channel#embed-object
type Embed struct {
	Title       string       `json:"title"`
	Description string       `json:"description"`
	Color       int          `json:"color"`
	Author      EmbedAuthor  `json:"author"`
	Fields      []EmbedField `json:"fields"`
	Timestamp   string       `json:"timestamp"`
}

// ----------- //
// Webhook API //
// ----------- //

// WebhookMessage https://discord.com/developers/docs/resources/webhook#execute-webhook
type WebhookMessage struct {
	Username  string  `json:"username"`
	AvatarURL string  `json:"avatar_url"`
	Embeds    []Embed `json:"embeds"`
}
