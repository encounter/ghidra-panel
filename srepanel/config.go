package main

import (
	"log"

	"go.mkw.re/ghidra-panel/common"
)

type config struct {
	BaseURL string `json:"base_url"`
	Discord struct {
		BotToken     string `json:"bot_token"`
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
		// TODO allow for more general webhooks
		// For now, we assume that the webhook is for Discord
		WebhookURL string `json:"webhook_url"`
	} `json:"discord"`
	Ghidra struct {
		Endpoint common.GhidraEndpoint `json:"endpoint"`
		RepoDir  string                `json:"repo_dir"`
	} `json:"ghidra"`
	Links []common.Link `json:"links"`
}

func (c *config) validate() {

	if c.Discord.ClientID == "" {
		log.Fatal("client_id not set")
	}
	if c.Discord.ClientSecret == "" {
		log.Fatal("client_secret not set")
	}
	if c.BaseURL == "" {
		log.Fatal("base_url not set")
	}
}
