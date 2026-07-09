package main

import (
	"errors"
	"os"

	"github.com/joho/godotenv"
)

type Config struct {
	issuerURL    string
	clientID     string
	clientSecret string
	redirectURL  string
}

func loadConfigParameters() (Config, error) {
	err := godotenv.Load()
	if err != nil {
		return Config{}, err
	}
	issuerURL := os.Getenv("ISSUER_URL")
	clientID := os.Getenv("CLIENT_ID")
	clientSecret := os.Getenv("CLIENT_SECRET")
	redirectURL := os.Getenv("REDIRECT_URL")

	config := Config{
		issuerURL:    issuerURL,
		clientID:     clientID,
		clientSecret: clientSecret,
		redirectURL:  redirectURL,
	}
	switch {
	case config.issuerURL == "":
		return Config{}, errors.New("Campo IssueURL vazio no .env")
	case config.clientID == "":
		return Config{}, errors.New("Campo clientID vazio no .env")
	case config.clientSecret == "":
		return Config{}, errors.New("Campo clientSecret vazio no .env")
	case config.redirectURL == "":
		return Config{}, errors.New("Campo redirectURL vazio no .env")
	}
	return config, nil
}
