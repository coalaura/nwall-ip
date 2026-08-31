package main

import (
	"bufio"
	"bytes"
	"cmp"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

const (
	rejectedStatus       = "444"
	rejectedRequestScore = uint64(1)
)

type AccessLogFile struct {
	Entry    os.DirEntry
	Rotation int
}

func SortedAccessLogs(entries []os.DirEntry) []AccessLogFile {
	logFiles := make([]AccessLogFile, 0, len(entries))

	for _, entry := range entries {
		rotation, ok := accessLogRotation(entry.Name())
		if !ok {
			continue
		}

		logFiles = append(logFiles, AccessLogFile{
			Entry:    entry,
			Rotation: rotation,
		})
	}

	slices.SortFunc(logFiles, func(left, right AccessLogFile) int {
		order := cmp.Compare(left.Rotation, right.Rotation)
		if order != 0 {
			return order
		}

		return cmp.Compare(left.Entry.Name(), right.Entry.Name())
	})

	return logFiles
}

func accessLogRotation(name string) (int, bool) {
	if name == "access.log" {
		return 0, true
	}

	suffix, ok := strings.CutPrefix(name, "access.log.")
	if !ok {
		return 0, false
	}

	suffix, _ = strings.CutSuffix(suffix, ".gz")
	if suffix == "" {
		return 0, false
	}

	for _, digit := range suffix {
		if digit < '0' || digit > '9' {
			return 0, false
		}
	}

	rotation, err := strconv.Atoi(suffix)
	if err != nil || rotation < 1 {
		return 0, false
	}

	return rotation, true
}

func FindScanBoundary(logFiles []AccessLogFile, cursor FileCursor, crawledTimestamp int64, logFormat LogFormat) (int, int64, error) {
	for i, logFile := range logFiles {
		path := filepath.Join(logDirectory, logFile.Entry.Name())

		info, err := logFile.Entry.Info()
		if err != nil {
			return 0, 0, fmt.Errorf("stat %s: %w", path, err)
		}

		if !info.Mode().IsRegular() {
			continue
		}

		if !strings.HasSuffix(path, ".gz") {
			device, inode, err := pathIdentity(path)
			if err != nil {
				return 0, 0, fmt.Errorf("identify %s: %w", path, err)
			}

			if cursor.Inode != 0 && device == cursor.Device && inode == cursor.Inode && cursor.Offset <= info.Size() {
				return i, cursor.Offset, nil
			}
		}

		firstTimestamp, ok, err := peekFirstTimestamp(path, logFormat)
		if err != nil {
			return 0, 0, fmt.Errorf("probe %s: %w", path, err)
		}

		if ok && firstTimestamp <= crawledTimestamp {
			return i, 0, nil
		}
	}

	return len(logFiles) - 1, 0, nil
}

func peekFirstTimestamp(path string, logFormat LogFormat) (timestamp int64, ok bool, returnErr error) {
	file, err := os.Open(path)
	if err != nil {
		return 0, false, err
	}

	defer func() {
		err := file.Close()
		if err != nil {
			returnErr = errors.Join(returnErr, fmt.Errorf("close file: %w", err))
		}
	}()

	var rd io.Reader = file

	if strings.HasSuffix(path, ".gz") {
		gzipReader, err := gzip.NewReader(file)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return 0, false, nil
			}

			return 0, false, fmt.Errorf("open gzip stream: %w", err)
		}

		defer func() {
			err := gzipReader.Close()
			if err != nil {
				returnErr = errors.Join(returnErr, fmt.Errorf("close gzip stream: %w", err))
			}
		}()

		rd = gzipReader
	}

	line, err := bufio.NewReaderSize(rd, 64<<10).ReadBytes('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return 0, false, fmt.Errorf("read first line: %w", err)
	}

	_, firstTimestamp, _, _, parsed := logFormat.Parse(line)
	if !parsed {
		return 0, false, nil
	}

	return firstTimestamp, true, nil
}

func CountFile(path string, startOffset, crawledTimestamp int64, statsByIP map[netip.Addr]IPStats, pathRules []PathScoreRule, logFormat LogFormat) (latestTimestamp int64, linesLookedAt uint64, cursor FileCursor, returnErr error) {
	file, err := os.Open(path)
	if err != nil {
		return 0, 0, FileCursor{}, err
	}

	defer func() {
		err := file.Close()
		if err != nil {
			returnErr = errors.Join(returnErr, fmt.Errorf("close file: %w", err))
		}
	}()

	cursor.Device, cursor.Inode, err = fileIdentity(file)
	if err != nil {
		return 0, 0, FileCursor{}, fmt.Errorf("identify open file: %w", err)
	}

	cursor.Offset = startOffset

	var rd io.Reader = file

	if strings.HasSuffix(path, ".gz") {
		gzipReader, err := gzip.NewReader(file)
		if err != nil {
			return 0, 0, FileCursor{}, fmt.Errorf("open gzip stream: %w", err)
		}

		defer func() {
			err := gzipReader.Close()
			if err != nil {
				returnErr = errors.Join(returnErr, fmt.Errorf("close gzip stream: %w", err))
			}
		}()

		rd = gzipReader
	} else if startOffset > 0 {
		_, err := file.Seek(startOffset, io.SeekStart)
		if err != nil {
			return 0, 0, FileCursor{}, fmt.Errorf("seek to offset %d: %w", startOffset, err)
		}
	}

	reader := bufio.NewReaderSize(rd, 64<<10)

	var partial []byte

	for {
		fragment, readErr := reader.ReadSlice('\n')

		if errors.Is(readErr, bufio.ErrBufferFull) {
			partial = append(partial, fragment...)

			continue
		}

		line := fragment

		if len(partial) > 0 {
			partial = append(partial, fragment...)

			line = partial
		}

		if len(line) > 0 && line[len(line)-1] == '\n' {
			cursor.Offset += int64(len(line))

			linesLookedAt++

			addr, requestTimestamp, requestPath, status, ok := logFormat.Parse(line)
			if ok {
				latestTimestamp = max(latestTimestamp, requestTimestamp)

				if requestTimestamp > crawledTimestamp {
					score, rejected := scoreRequest(requestPath, status, pathRules)
					if score > 0 {
						stats := statsByIP[addr]

						stats.Score += score

						if rejected {
							stats.Rejected++
						}

						statsByIP[addr] = stats
					}
				}
			}
		}

		partial = partial[:0]

		if readErr == nil {
			continue
		}

		if errors.Is(readErr, io.EOF) {
			return latestTimestamp, linesLookedAt, cursor, nil
		}

		return latestTimestamp, linesLookedAt, cursor, fmt.Errorf("read log: %w", readErr)
	}
}

func scoreRequest(path, status []byte, pathRules []PathScoreRule) (score uint64, rejected bool) {
	rejected = bytes.Equal(status, []byte(rejectedStatus))
	if rejected {
		score += rejectedRequestScore
	}

	for _, rule := range pathRules {
		pattern := []byte(rule.Pattern)

		var matched bool

		switch rule.Match {
		case PathStartsWith:
			matched = bytes.HasPrefix(path, pattern)
		case PathEndsWith:
			matched = bytes.HasSuffix(path, pattern)
		case PathContains:
			matched = bytes.Contains(path, pattern)
		}

		if matched {
			score += rule.Score
		}
	}

	return score, rejected
}

func pathIdentity(path string) (uint64, uint64, error) {
	var stat unix.Stat_t

	err := unix.Stat(path, &stat)
	if err != nil {
		return 0, 0, err
	}

	return uint64(stat.Dev), uint64(stat.Ino), nil
}

func fileIdentity(file *os.File) (uint64, uint64, error) {
	var stat unix.Stat_t

	err := unix.Fstat(int(file.Fd()), &stat)
	if err != nil {
		return 0, 0, err
	}

	return uint64(stat.Dev), uint64(stat.Ino), nil
}
