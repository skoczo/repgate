package config

import (
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	AbuseIPDB struct {
		Enabled                  bool          `yaml:"enabled"`
		APIKey                   string        `yaml:"api_key"`
		ExpirationTime           time.Duration `yaml:"expiration_time"`
		ConfidenceScoreThreshold int           `yaml:"confidence_score_threshold"`
	} `yaml:"AbuseIPDB"`
}

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}
