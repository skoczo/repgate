package config

import (
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	LogLevel  string `yaml:"log_level"`
	FailOpen  bool   `yaml:"fail_open"`
	AbuseIPDB struct {
		Enabled                  bool          `yaml:"enabled"`
		APIKey                   string        `yaml:"api_key"`
		ExpirationTime           time.Duration `yaml:"expiration_time"`
		ConfidenceScoreThreshold int           `yaml:"confidence_score_threshold"`
		CacheMaxSize             int           `yaml:"cache_max_size"`
		CircuitBreaker           struct {
			MaxRetries     int           `yaml:"max_retries"`
			CoolDownPeriod time.Duration `yaml:"cool_down_period"`
			OpenOnError    bool          `yaml:"open_on_error"`
		} `yaml:"circuit_breaker"`
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
