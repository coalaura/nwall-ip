package main

import (
	"bytes"
	"fmt"
	"net/netip"
	"time"
)

const (
	logTimeLayout    = "02/Jan/2006:15:04:05 -0700"
	defaultLogFormat = `$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"`

	logCaptureIgnored = -1
	logCaptureAddr    = 0
	logCaptureTime    = 1
	logCaptureRequest = 2
	logCaptureStatus  = 3
	logCaptureCount   = 4
)

type LogFormatToken struct {
	Literal []byte
	Capture int
	Field   bool
}

type LogFormat struct {
	Tokens []LogFormatToken
}

func (format LogFormat) Parse(line []byte) (netip.Addr, int64, []byte, []byte, bool) {
	var captures [logCaptureCount][]byte

	position := 0
	lineEnd := len(line)

	for lineEnd > 0 && (line[lineEnd-1] == '\n' || line[lineEnd-1] == '\r') {
		lineEnd--
	}

	for i, token := range format.Tokens {
		if !token.Field {
			if position > lineEnd {
				return netip.Addr{}, 0, nil, nil, false
			}

			if !bytes.HasPrefix(line[position:lineEnd], token.Literal) {
				return netip.Addr{}, 0, nil, nil, false
			}

			position += len(token.Literal)

			continue
		}

		fieldEnd := lineEnd

		if i+1 < len(format.Tokens) {
			if position > lineEnd {
				return netip.Addr{}, 0, nil, nil, false
			}

			nextLiteral := format.Tokens[i+1].Literal
			offset := bytes.Index(line[position:lineEnd], nextLiteral)

			if offset < 0 {
				return netip.Addr{}, 0, nil, nil, false
			}

			fieldEnd = position + offset
		}

		if token.Capture != logCaptureIgnored {
			captures[token.Capture] = line[position:fieldEnd]
		}

		position = fieldEnd
	}

	if position != lineEnd {
		return netip.Addr{}, 0, nil, nil, false
	}

	addr, err := netip.ParseAddr(string(captures[logCaptureAddr]))
	if err != nil {
		return netip.Addr{}, 0, nil, nil, false
	}

	requestTime, err := time.Parse(logTimeLayout, string(captures[logCaptureTime]))
	if err != nil {
		return netip.Addr{}, 0, nil, nil, false
	}

	path, ok := requestPath(captures[logCaptureRequest])
	if !ok {
		return netip.Addr{}, 0, nil, nil, false
	}

	return addr.Unmap(), requestTime.Unix(), path, captures[logCaptureStatus], true
}

func CompileLogFormat(value string) (LogFormat, error) {
	if value == "" {
		value = defaultLogFormat
	}

	tokens := make([]LogFormatToken, 0, 16)
	seenCaptures := [logCaptureCount]bool{}
	literalStart := 0

	for position := 0; position < len(value); {
		if value[position] != '$' {
			position++

			continue
		}

		if position > literalStart {
			tokens = append(tokens, LogFormatToken{Literal: []byte(value[literalStart:position])})
		}

		variableStart := position
		position++

		nameStart := position
		nameEnd := position

		if position < len(value) && value[position] == '{' {
			nameStart = position + 1
			nameEnd = nameStart

			for nameEnd < len(value) && isLogVariableCharacter(value[nameEnd]) {
				nameEnd++
			}

			if nameEnd == nameStart || nameEnd >= len(value) || value[nameEnd] != '}' {
				return LogFormat{}, fmt.Errorf("invalid variable at byte %d", variableStart+1)
			}

			position = nameEnd + 1
		} else {
			for nameEnd < len(value) && isLogVariableCharacter(value[nameEnd]) {
				nameEnd++
			}

			if nameEnd == nameStart {
				return LogFormat{}, fmt.Errorf("invalid variable at byte %d", variableStart+1)
			}

			position = nameEnd
		}

		if len(tokens) > 0 && tokens[len(tokens)-1].Field {
			return LogFormat{}, fmt.Errorf("variables at byte %d need a literal separator", variableStart+1)
		}

		variable := value[nameStart:nameEnd]
		capture := logCapture(variable)

		if capture != logCaptureIgnored {
			if seenCaptures[capture] {
				return LogFormat{}, fmt.Errorf("variable $%s occurs more than once", variable)
			}

			seenCaptures[capture] = true
		}

		tokens = append(tokens, LogFormatToken{Capture: capture, Field: true})
		literalStart = position
	}

	if literalStart < len(value) {
		tokens = append(tokens, LogFormatToken{Literal: []byte(value[literalStart:])})
	}

	requiredVariables := [...]string{"remote_addr", "time_local", "request", "status"}

	for capture, variable := range requiredVariables {
		if !seenCaptures[capture] {
			return LogFormat{}, fmt.Errorf("missing required variable $%s", variable)
		}
	}

	return LogFormat{Tokens: tokens}, nil
}

func logCapture(variable string) int {
	switch variable {
	case "remote_addr":
		return logCaptureAddr
	case "time_local":
		return logCaptureTime
	case "request":
		return logCaptureRequest
	case "status":
		return logCaptureStatus
	default:
		return logCaptureIgnored
	}
}

func isLogVariableCharacter(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' || value >= '0' && value <= '9' || value == '_'
}

func requestPath(request []byte) ([]byte, bool) {
	position := skipSpace(request, 0)
	methodStart := position

	for position < len(request) && !isSpace(request[position]) {
		position++
	}

	if position == methodStart {
		return nil, false
	}

	position = skipSpace(request, position)
	targetStart := position

	for position < len(request) && !isSpace(request[position]) {
		position++
	}

	if position == targetStart {
		return nil, false
	}

	target := request[targetStart:position]
	path := target

	// Handle absolute-form request targets such as
	// "GET http://example.com/path HTTP/1.1".
	if target[0] != '/' {
		schemeEnd := bytes.Index(target, []byte("://"))
		if schemeEnd >= 0 {
			authorityStart := schemeEnd + len("://")

			slashOffset := bytes.IndexByte(target[authorityStart:], '/')
			if slashOffset < 0 {
				path = []byte("/")
			} else {
				path = target[authorityStart+slashOffset:]
			}
		}
	}

	// Path rules intentionally do not inspect the query string or fragment.
	pathEnd := bytes.IndexAny(path, "?#")
	if pathEnd >= 0 {
		path = path[:pathEnd]
	}

	return path, len(path) > 0
}

func skipSpace(line []byte, position int) int {
	for position < len(line) && isSpace(line[position]) {
		position++
	}

	return position
}

func isSpace(value byte) bool {
	return value == ' ' || value == '\t'
}
