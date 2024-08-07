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
		WebhookURL   string `json:"webhook_url"`
	} `json:"discord"`
	Ghidra struct {
		Endpoint common.GhidraEndpoint `json:"endpoint"`
		GRPCAddr string                `json:"grpc_addr"`
	} `json:"ghidra"`
	Links       []common.Link `json:"links"`
	SuperAdmins []uint64      `json:"super_admins"`
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
