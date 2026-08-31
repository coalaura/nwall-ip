package main

import (
	"cmp"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

const (
	logDirectory   = "/var/log/nginx"
	configFileName = "config.yml"
	outputFileName = "nwall_ip.log"
)

func main() {
	err := run(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "nwall_ip: %v\n", err)

		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) > 0 {
		if len(args) == 1 && args[0] == "remove" {
			return removeFirewall()
		}

		return fmt.Errorf("usage: nwall_ip [remove]")
	}

	executableDirectory, err := findExecutableDirectory()
	if err != nil {
		return err
	}

	configPath := filepath.Join(executableDirectory, configFileName)

	config, err := LoadConfig(configPath)
	if err != nil {
		return err
	}

	err = validateConfig(config)
	if err != nil {
		return err
	}

	logFormat, err := CompileLogFormat(config.AccessLog.Format)
	if err != nil {
		return fmt.Errorf("access_log.format: %w", err)
	}

	minimumScore := config.BlockScore

	if minimumScore == 0 {
		minimumScore = defaultBlockScore
	}

	whitelist, err := LoadIPWhitelist(config.Whitelist)
	if err != nil {
		return err
	}

	fmt.Printf("whitelist=%d\n", len(whitelist))

	databasePath := filepath.Join(executableDirectory, outputFileName)

	crawledTimestamp, cursor, statsByIP, err := LoadDatabase(databasePath)
	if err != nil {
		return err
	}

	entries, err := os.ReadDir(logDirectory)
	if err != nil {
		return fmt.Errorf("read %s: %w", logDirectory, err)
	}

	logFiles := SortedAccessLogs(entries)
	if len(logFiles) == 0 {
		return fmt.Errorf("no access log files found in %s", logDirectory)
	}

	boundaryIndex, resumeOffset, err := FindScanBoundary(logFiles, cursor, crawledTimestamp, logFormat)
	if err != nil {
		return err
	}

	var (
		files           int
		linesLookedAt   uint64
		latestTimestamp = crawledTimestamp

		nextCursor     FileCursor
		cursorRecorded bool
	)

	for i := 0; i <= boundaryIndex; i++ {
		entry := logFiles[i].Entry
		path := filepath.Join(logDirectory, entry.Name())

		info, err := entry.Info()
		if err != nil {
			return fmt.Errorf("stat %s: %w", path, err)
		}

		if !info.Mode().IsRegular() {
			continue
		}

		startOffset := int64(0)

		if i == boundaryIndex {
			startOffset = resumeOffset
		}

		fileTimestamp, fileLines, fileCursor, err := CountFile(path, startOffset, crawledTimestamp, statsByIP, config.PathRules, logFormat)
		if err != nil {
			return fmt.Errorf("process %s: %w", path, err)
		}

		latestTimestamp = max(latestTimestamp, fileTimestamp)

		linesLookedAt += fileLines

		files++

		if !cursorRecorded && !strings.HasSuffix(path, ".gz") {
			nextCursor = fileCursor

			cursorRecorded = true
		}

		fmt.Printf("scanned file=%s lines=%d newest_request=%d offset=%d\n", entry.Name(), fileLines, fileTimestamp, fileCursor.Offset)
	}

	skippedFiles := len(logFiles) - boundaryIndex - 1

	if files == 0 {
		return fmt.Errorf("no regular access log files found in %s", logDirectory)
	}

	results := make([]IPResult, 0, len(statsByIP))

	var totalScore uint64

	for addr, stats := range statsByIP {
		results = append(results, IPResult{
			Addr:    addr,
			IPStats: stats,
		})

		totalScore += stats.Score
	}

	slices.SortFunc(results, func(left, right IPResult) int {
		order := cmp.Compare(right.Score, left.Score)
		if order != 0 {
			return order
		}

		order = cmp.Compare(right.Rejected, left.Rejected)
		if order != 0 {
			return order
		}

		return left.Addr.Compare(right.Addr)
	})

	err = WriteDatabase(databasePath, latestTimestamp, nextCursor, totalScore, results)
	if err != nil {
		return err
	}

	err = ApplyFirewall(results, whitelist, minimumScore)
	if err != nil {
		return err
	}

	blocked := 0

	for _, result := range results {
		if ShouldBlock(result, whitelist, minimumScore) {
			blocked++
		}
	}

	fmt.Printf("Scanned %d lines across %d files, skipped %d older files, tracked %d IPs and blocked %d.\n", linesLookedAt, files, skippedFiles, len(results), blocked)

	return nil
}

func findExecutableDirectory() (string, error) {
	executable, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("locate executable: %w", err)
	}

	executable, err = filepath.EvalSymlinks(executable)
	if err != nil {
		return "", fmt.Errorf("resolve executable path: %w", err)
	}

	return filepath.Dir(executable), nil
}
