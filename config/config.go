package config

import (
	"fmt"
	"os"
	"time"

	"github.com/joho/godotenv"
)

type Config struct {
	Server struct {
		Port         string
		ReadTimeout  time.Duration
		WriteTimeout time.Duration
		IdleTimeout  time.Duration
	}
	Session struct {
		SecretKey       string
		Name            string
		Secure          bool
		HttpOnly        bool
		SameSite        string
		IdleTimeout     time.Duration
		AbsoluteTimeout time.Duration
	}
	Database struct {
		Path string
	}
}

func Load() (*Config, error) {
	// Load .env file if it exists
	_ = godotenv.Load()

	var config Config

	// Server configuration
	config.Server.Port = getEnv("SERVER_PORT", "8080")
	config.Server.ReadTimeout = 10 * time.Second
	config.Server.WriteTimeout = 10 * time.Second
	config.Server.IdleTimeout = 120 * time.Second

	// Session configuration
	config.Session.SecretKey = getEnv("SESSION_SECRET", "")
	if config.Session.SecretKey == "" {
		return nil, fmt.Errorf("SESSION_SECRET environment variable is required")
	}

	config.Session.Name = getEnv("SESSION_NAME", "session-name")
	config.Session.Secure = getEnv("SESSION_SECURE", "true") == "true"
	config.Session.HttpOnly = getEnv("SESSION_HTTP_ONLY", "true") == "true"
	config.Session.SameSite = getEnv("SESSION_SAME_SITE", "Lax")
	config.Session.IdleTimeout = 30 * time.Minute
	config.Session.AbsoluteTimeout = 24 * time.Hour

	// Database configuration
	config.Database.Path = getEnv("DATABASE_PATH", "data/site.db")

	return &config, nil
}

func getEnv(key, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultValue
}
