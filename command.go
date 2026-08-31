package main

import (
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
)

func commandSucceeds(name string, args ...string) (bool, error) {
	command := exec.Command(name, args...)

	output, err := command.CombinedOutput()
	if err == nil {
		return true, nil
	}

	exitErr, ok := errors.AsType[*exec.ExitError](err)
	if ok {
		if exitErr.ExitCode() == 1 {
			return false, nil
		}
	}

	return false, commandError(name, args, output, err)
}

func runCommand(stdin io.Reader, name string, args ...string) error {
	_, err := runCommandOutput(stdin, name, args...)

	return err
}

func runCommandOutput(stdin io.Reader, name string, args ...string) ([]byte, error) {
	command := exec.Command(name, args...)

	command.Stdin = stdin

	output, err := command.CombinedOutput()
	if err != nil {
		return nil, commandError(name, args, output, err)
	}

	return output, nil
}

func commandError(name string, args []string, output []byte, err error) error {
	message := strings.TrimSpace(string(output))
	if message == "" {
		return fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
	}

	return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, message)
}
