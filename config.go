package main

import (
	"errors"
	"fmt"
	"io"
	"net/netip"
	"net/url"
	"os"
	"strings"

	"github.com/goccy/go-yaml"
)

type PathMatch string

const (
	PathStartsWith PathMatch = "startswith"
	PathEndsWith   PathMatch = "endswith"
	PathContains   PathMatch = "contains"
)

type PathScoreRule struct {
	Match   PathMatch `yaml:"match"`
	Pattern string    `yaml:"pattern"`
	Score   uint64    `yaml:"score"`
}

type Config struct {
	AccessLog  AccessLogConfig `yaml:"access_log"`
	PathRules  []PathScoreRule `yaml:"path_rules"`
	Whitelist  WhitelistConfig `yaml:"whitelist"`
	BlockScore uint64          `yaml:"block_score"`
}

type AccessLogConfig struct {
	Format string `yaml:"format"`
}

type WhitelistConfig struct {
	IPs  []string `yaml:"ips"`
	URLs []string `yaml:"urls"`
}

func LoadConfig(path string) (config Config, returnErr error) {
	file, err := os.Open(path)
	if err != nil {
		return Config{}, fmt.Errorf("open config %s: %w", path, err)
	}

	defer func() {
		err := file.Close()
		if err != nil {
			returnErr = errors.Join(returnErr, fmt.Errorf("close config %s: %w", path, err))
		}
	}()

	decoder := yaml.NewDecoder(file, yaml.DisallowUnknownField())

	err = decoder.Decode(&config)
	if err != nil {
		return Config{}, fmt.Errorf("decode config %s: %w", path, err)
	}

	var extra any

	err = decoder.Decode(&extra)
	if err == nil {
		return Config{}, fmt.Errorf("decode config %s: multiple YAML documents are not supported", path)
	}

	if !errors.Is(err, io.EOF) {
		return Config{}, fmt.Errorf("decode config %s: %w", path, err)
	}

	return config, nil
}

func validateConfig(config Config) error {
	for i, rule := range config.PathRules {
		if rule.Pattern == "" {
			return fmt.Errorf("path score rule %d has an empty pattern", i+1)
		}

		switch rule.Match {
		case PathStartsWith, PathEndsWith, PathContains:
		default:
			return fmt.Errorf("path score rule %d has unsupported match operation %q", i+1, rule.Match)
		}
	}

	for i, value := range config.Whitelist.IPs {
		value = strings.TrimSpace(value)

		_, err := netip.ParseAddr(value)
		if err != nil {
			return fmt.Errorf("whitelist.ips entry %d is invalid: %q", i+1, value)
		}
	}

	for i, whitelistURL := range config.Whitelist.URLs {
		whitelistURL = strings.TrimSpace(whitelistURL)
		if whitelistURL == "" {
			return fmt.Errorf("whitelist.urls entry %d is empty", i+1)
		}

		parsedURL, err := url.ParseRequestURI(whitelistURL)
		if err != nil || parsedURL.Host == "" || (parsedURL.Scheme != "http" && parsedURL.Scheme != "https") {
			return fmt.Errorf("whitelist.urls entry %d is invalid: %q", i+1, whitelistURL)
		}
	}

	return nil
}
