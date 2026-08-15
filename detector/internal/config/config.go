package config

import (
	"fmt"
	"os"
	"time"

	"go.yaml.in/yaml/v3"
)

type Rule struct {
	Enabled  bool   `yaml:"enabled"`
	Severity string `yaml:"severity"`
}
type RateLimit struct {
	Rule       `yaml:",inline"`
	Requests   int           `yaml:"requests"`
	Window     time.Duration `yaml:"-"`
	WindowText string        `yaml:"window"`
}
type Anomaly struct {
	Rule           `yaml:",inline"`
	Alpha          float64       `yaml:"alpha"`
	ZThreshold     float64       `yaml:"z_threshold"`
	MinimumSamples int           `yaml:"minimum_samples"`
	StateTTL       time.Duration `yaml:"-"`
	StateTTLText   string        `yaml:"state_ttl"`
}
type Credential struct {
	Rule       `yaml:",inline"`
	Failures   int           `yaml:"failures"`
	Window     time.Duration `yaml:"-"`
	WindowText string        `yaml:"window"`
}
type Scraping struct {
	Rule           `yaml:",inline"`
	SequenceLength int           `yaml:"sequence_length"`
	MaxIDGap       int           `yaml:"max_id_gap"`
	StateTTL       time.Duration `yaml:"-"`
	StateTTLText   string        `yaml:"state_ttl"`
}
type Whitelist struct {
	SourceIPs []string `yaml:"source_ips"`
	CIDRs     []string `yaml:"cidrs"`
	Endpoints []string `yaml:"endpoints"`
}
type Config struct {
	RateLimit  RateLimit  `yaml:"rate_limit"`
	Anomaly    Anomaly    `yaml:"anomaly"`
	Credential Credential `yaml:"credential_stuffing"`
	Scraping   Scraping   `yaml:"scraping"`
	Signatures Rule       `yaml:"signatures"`
	Whitelist  Whitelist  `yaml:"whitelist"`
}

func Load(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read rules: %w", err)
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("parse rules: %w", err)
	}
	if cfg.RateLimit.Window, err = time.ParseDuration(cfg.RateLimit.WindowText); err != nil {
		return Config{}, fmt.Errorf("rate_limit.window: %w", err)
	}
	if cfg.Credential.Window, err = time.ParseDuration(cfg.Credential.WindowText); err != nil {
		return Config{}, fmt.Errorf("credential_stuffing.window: %w", err)
	}
	if cfg.Anomaly.StateTTL, err = time.ParseDuration(cfg.Anomaly.StateTTLText); err != nil {
		return Config{}, fmt.Errorf("anomaly.state_ttl: %w", err)
	}
	if cfg.Scraping.StateTTL, err = time.ParseDuration(cfg.Scraping.StateTTLText); err != nil {
		return Config{}, fmt.Errorf("scraping.state_ttl: %w", err)
	}
	if cfg.RateLimit.Requests < 1 || cfg.Credential.Failures < 1 || cfg.Scraping.SequenceLength < 2 || cfg.Anomaly.Alpha <= 0 || cfg.Anomaly.Alpha > 1 || cfg.Anomaly.MinimumSamples < 2 {
		return Config{}, fmt.Errorf("rule thresholds are outside valid ranges")
	}
	return cfg, nil
}
