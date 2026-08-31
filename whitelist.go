package main

import (
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"time"
	"unicode"
)

const (
	whitelistMaxBytes = int64(10 << 20)
	whitelistTimeout  = 15 * time.Second
)

func LoadIPWhitelist(config WhitelistConfig) (map[netip.Addr]struct{}, error) {
	whitelist := make(map[netip.Addr]struct{}, len(config.IPs))

	for _, value := range config.IPs {
		addr := netip.MustParseAddr(strings.TrimSpace(value))

		whitelist[addr.Unmap()] = struct{}{}
	}

	client := http.Client{
		Timeout: whitelistTimeout,
	}

	for _, whitelistURL := range config.URLs {
		whitelistURL = strings.TrimSpace(whitelistURL)

		response, err := client.Get(whitelistURL)
		if err != nil {
			return nil, fmt.Errorf("fetch IP whitelist %s: %w", whitelistURL, err)
		}

		if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
			response.Body.Close()

			return nil, fmt.Errorf("fetch IP whitelist %s: unexpected HTTP status %s", whitelistURL, response.Status)
		}

		limitedBody := io.LimitReader(response.Body, whitelistMaxBytes+1)

		body, readErr := io.ReadAll(limitedBody)
		closeErr := response.Body.Close()

		if readErr != nil {
			return nil, fmt.Errorf("read IP whitelist %s: %w", whitelistURL, readErr)
		}

		if closeErr != nil {
			return nil, fmt.Errorf("close IP whitelist %s: %w", whitelistURL, closeErr)
		}

		if int64(len(body)) > whitelistMaxBytes {
			return nil, fmt.Errorf("IP whitelist %s exceeds %d bytes", whitelistURL, whitelistMaxBytes)
		}

		err = addIPWhitelist(whitelist, whitelistURL, body)
		if err != nil {
			return nil, err
		}
	}

	return whitelist, nil
}

func addIPWhitelist(whitelist map[netip.Addr]struct{}, source string, body []byte) error {
	values := strings.FieldsFunc(string(body), isIPWhitelistBoundary)

	addresses := 0

	for _, value := range values {
		addr, err := netip.ParseAddr(value)
		if err != nil {
			continue
		}

		whitelist[addr.Unmap()] = struct{}{}

		addresses++
	}

	if addresses == 0 {
		return fmt.Errorf("IP whitelist %s contains no IP addresses", source)
	}

	return nil
}

func isIPWhitelistBoundary(value rune) bool {
	return unicode.IsSpace(value) || value == '<' || value == '>' || value == '"' || value == '\''
}
