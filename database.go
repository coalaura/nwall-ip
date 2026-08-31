package main

import (
	"bufio"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type IPStats struct {
	Score    uint64
	Rejected uint64
}

type IPResult struct {
	Addr netip.Addr
	IPStats
}

type FileCursor struct {
	Device uint64
	Inode  uint64
	Offset int64
}

func LoadDatabase(path string) (timestamp int64, cursor FileCursor, statsByIP map[netip.Addr]IPStats, returnErr error) {
	statsByIP = make(map[netip.Addr]IPStats)

	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return 0, FileCursor{}, statsByIP, nil
	}

	if err != nil {
		return 0, FileCursor{}, nil, fmt.Errorf("open database %s: %w", path, err)
	}

	defer func() {
		err := file.Close()
		if err != nil {
			returnErr = errors.Join(returnErr, fmt.Errorf("close database: %w", err))
		}
	}()

	scanner := bufio.NewScanner(file)

	scanner.Buffer(make([]byte, 4096), 1<<20)

	if !scanner.Scan() {
		err = scanner.Err()
		if err != nil {
			return 0, FileCursor{}, nil, fmt.Errorf("read database header: %w", err)
		}

		return 0, FileCursor{}, nil, fmt.Errorf("database %s is empty", path)
	}

	// Databases written before cursor support only carry time and total; a
	// zero cursor falls back to the timestamp probe on the next scan.
	header := strings.Fields(scanner.Text())
	if len(header) != 2 && len(header) != 5 {
		return 0, FileCursor{}, nil, fmt.Errorf("database has an invalid header")
	}

	timestampValue, ok := databaseField(header[0], "time")
	if !ok {
		return 0, FileCursor{}, nil, fmt.Errorf("database header is missing time")
	}

	timestamp, err = strconv.ParseInt(timestampValue, 10, 64)
	if err != nil || timestamp < 0 {
		return 0, FileCursor{}, nil, fmt.Errorf("database has invalid time %q", timestampValue)
	}

	totalValue, ok := databaseField(header[1], "total")
	if !ok {
		return 0, FileCursor{}, nil, fmt.Errorf("database header is missing total")
	}

	expectedTotal, err := strconv.ParseUint(totalValue, 10, 64)
	if err != nil {
		return 0, FileCursor{}, nil, fmt.Errorf("database has invalid total %q", totalValue)
	}

	if len(header) == 5 {
		deviceValue, ok := databaseField(header[2], "dev")
		if !ok {
			return 0, FileCursor{}, nil, fmt.Errorf("database header is missing dev")
		}

		cursor.Device, err = strconv.ParseUint(deviceValue, 10, 64)
		if err != nil {
			return 0, FileCursor{}, nil, fmt.Errorf("database has invalid dev %q", deviceValue)
		}

		inodeValue, ok := databaseField(header[3], "ino")
		if !ok {
			return 0, FileCursor{}, nil, fmt.Errorf("database header is missing ino")
		}

		cursor.Inode, err = strconv.ParseUint(inodeValue, 10, 64)
		if err != nil {
			return 0, FileCursor{}, nil, fmt.Errorf("database has invalid ino %q", inodeValue)
		}

		offsetValue, ok := databaseField(header[4], "offset")
		if !ok {
			return 0, FileCursor{}, nil, fmt.Errorf("database header is missing offset")
		}

		cursor.Offset, err = strconv.ParseInt(offsetValue, 10, 64)
		if err != nil || cursor.Offset < 0 {
			return 0, FileCursor{}, nil, fmt.Errorf("database has invalid offset %q", offsetValue)
		}
	}

	if !scanner.Scan() {
		err = scanner.Err()
		if err != nil {
			return 0, FileCursor{}, nil, fmt.Errorf("read database separator: %w", err)
		}

		return 0, FileCursor{}, nil, fmt.Errorf("database is missing its separator")
	}

	if strings.TrimSpace(scanner.Text()) != "---" {
		return 0, FileCursor{}, nil, fmt.Errorf("database has an invalid separator")
	}

	var (
		actualTotal uint64
		lineNumber  = 2
	)

	for scanner.Scan() {
		lineNumber++

		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) != 3 {
			return 0, FileCursor{}, nil, fmt.Errorf("database line %d is invalid", lineNumber)
		}

		ipValue, ok := databaseField(fields[0], "ip")
		if !ok {
			return 0, FileCursor{}, nil, fmt.Errorf("database line %d is missing ip", lineNumber)
		}

		addr, err := netip.ParseAddr(ipValue)
		if err != nil {
			return 0, FileCursor{}, nil, fmt.Errorf("database line %d has invalid ip %q", lineNumber, ipValue)
		}

		addr = addr.Unmap()

		if _, exists := statsByIP[addr]; exists {
			return 0, FileCursor{}, nil, fmt.Errorf("database line %d duplicates ip %s", lineNumber, addr)
		}

		scoreValue, ok := databaseField(fields[1], "score")
		if !ok {
			return 0, FileCursor{}, nil, fmt.Errorf("database line %d is missing score", lineNumber)
		}

		score, err := strconv.ParseUint(scoreValue, 10, 64)
		if err != nil {
			return 0, FileCursor{}, nil, fmt.Errorf("database line %d has invalid score %q", lineNumber, scoreValue)
		}

		rejectedValue, ok := databaseField(fields[2], "rejected")
		if !ok {
			return 0, FileCursor{}, nil, fmt.Errorf("database line %d is missing rejected", lineNumber)
		}

		rejected, err := strconv.ParseUint(rejectedValue, 10, 64)
		if err != nil {
			return 0, FileCursor{}, nil, fmt.Errorf("database line %d has invalid rejected count %q", lineNumber, rejectedValue)
		}

		if ^uint64(0)-actualTotal < score {
			return 0, FileCursor{}, nil, fmt.Errorf("database total score overflows uint64")
		}

		actualTotal += score

		statsByIP[addr] = IPStats{
			Score:    score,
			Rejected: rejected,
		}
	}

	err = scanner.Err()
	if err != nil {
		return 0, FileCursor{}, nil, fmt.Errorf("read database: %w", err)
	}

	if actualTotal != expectedTotal {
		return 0, FileCursor{}, nil, fmt.Errorf("database total is %d, but entries total %d", expectedTotal, actualTotal)
	}

	return timestamp, cursor, statsByIP, nil
}

func WriteDatabase(path string, timestamp int64, cursor FileCursor, totalScore uint64, results []IPResult) (returnErr error) {
	directory := filepath.Dir(path)

	file, err := os.CreateTemp(directory, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temporary database: %w", err)
	}

	var closed bool

	temporaryPath := file.Name()

	defer func() {
		if !closed {
			err := file.Close()
			if err != nil {
				returnErr = errors.Join(
					returnErr,
					fmt.Errorf("close temporary database: %w", err),
				)
			}
		}

		err := os.Remove(temporaryPath)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			returnErr = errors.Join(
				returnErr,
				fmt.Errorf("remove temporary database: %w", err),
			)
		}
	}()

	err = file.Chmod(0o640)
	if err != nil {
		return fmt.Errorf("set database permissions: %w", err)
	}

	writer := bufio.NewWriter(file)

	_, err = fmt.Fprintf(writer, "time=%d total=%d dev=%d ino=%d offset=%d\n---\n", timestamp, totalScore, cursor.Device, cursor.Inode, cursor.Offset)
	if err != nil {
		return fmt.Errorf("write database header: %w", err)
	}

	for _, result := range results {
		_, err := fmt.Fprintf(writer, "ip=%s score=%d rejected=%d\n", result.Addr, result.Score, result.Rejected)
		if err != nil {
			return fmt.Errorf("write database entry: %w", err)
		}
	}

	err = writer.Flush()
	if err != nil {
		return fmt.Errorf("flush database: %w", err)
	}

	err = file.Sync()
	if err != nil {
		return fmt.Errorf("sync database: %w", err)
	}

	err = file.Close()

	closed = true

	if err != nil {
		return fmt.Errorf("close database: %w", err)
	}

	err = os.Rename(temporaryPath, path)
	if err != nil {
		return fmt.Errorf("replace database: %w", err)
	}

	return nil
}

func databaseField(field, name string) (string, bool) {
	return strings.CutPrefix(field, name+"=")
}
