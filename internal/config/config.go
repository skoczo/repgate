package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	AbuseIPDB struct {
		Enabled bool   `yaml:"enabled"`
		APIKey  string `yaml:"api_key"`
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
