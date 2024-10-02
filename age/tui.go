// These functions have been copied from the age project
// https://github.com/FiloSottile/age/blob/v1.0.0/cmd/age/encrypted_keys.go
// https://github.com/FiloSottile/age/blob/266c0940916da6bfa310fdd23156fbd70f9d90a0/tui/tui.go
//
// Copyright 2021 The age Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in age's LICENSE file at
// https://github.com/FiloSottile/age/blob/v1.0.0/LICENSE
//
// SPDX-License-Identifier: BSD-3-Clause

package age

import (
	"errors"
	"filippo.io/age/plugin"
	"fmt"
	"io"
	"os"
	"runtime"
	"testing"

	"golang.org/x/term"
)

const (
	SopsAgePasswordEnv = "SOPS_AGE_PASSWORD"
)

// readPassphrase reads a passphrase from the terminal. It does not read from a
// non-terminal stdin, so it does not check stdinInUse.
func readPassphrase(prompt string) ([]byte, error) {
	if testing.Testing() {
		password := os.Getenv(SopsAgePasswordEnv)
		if password != "" {
			return []byte(password), nil
		}
	}

	var in, out *os.File
	if runtime.GOOS == "windows" {
		var err error
		in, err = os.OpenFile("CONIN$", os.O_RDWR, 0)
		if err != nil {
			return nil, err
		}
		defer in.Close()
		out, err = os.OpenFile("CONOUT$", os.O_WRONLY, 0)
		if err != nil {
			return nil, err
		}
		defer out.Close()
	} else if _, err := os.Stat("/dev/tty"); err == nil {
		tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
		if err != nil {
			return nil, err
		}
		defer tty.Close()
		in, out = tty, tty
	} else {
		if !term.IsTerminal(int(os.Stdin.Fd())) {
			return nil, fmt.Errorf("standard input is not a terminal, and /dev/tty is not available: %v", err)
		}
		in, out = os.Stdin, os.Stderr
	}
	fmt.Fprintf(out, "%s ", prompt)
	// Use CRLF to work around an apparent bug in WSL2's handling of CONOUT$.
	// Only when running a Windows binary from WSL2, the cursor would not go
	// back to the start of the line with a simple LF. Honestly, it's impressive
	// CONIN$ and CONOUT$ even work at all inside WSL2.
	defer fmt.Fprintf(out, "\r\n")
	return term.ReadPassword(int(in.Fd()))
}

func Printf(format string, v ...interface{}) {
	log.Printf("age: "+format, v...)
}

func Warningf(format string, v ...interface{}) {
	log.Printf("age: warning: "+format, v...)
}

// ClearLine clears the current line on the terminal, or opens a new line if
// terminal escape codes don't work.
func ClearLine(out io.Writer) {
	const (
		CUI = "\033["   // Control Sequence Introducer
		CPL = CUI + "F" // Cursor Previous Line
		EL  = CUI + "K" // Erase in Line
	)

	// First, open a new line, which is guaranteed to work everywhere. Then, try
	// to erase the line above with escape codes.
	//
	// (We use CRLF instead of LF to work around an apparent bug in WSL2's
	// handling of CONOUT$. Only when running a Windows binary from WSL2, the
	// cursor would not go back to the start of the line with a simple LF.
	// Honestly, it's impressive CONIN$ and CONOUT$ work at all inside WSL2.)
	fmt.Fprintf(out, "\r\n"+CPL+EL)
}

// WithTerminal runs f with the terminal input and output files, if available.
// WithTerminal does not open a non-terminal stdin, so the caller does not need
// to check stdinInUse.
func WithTerminal(f func(in, out *os.File) error) error {
	if runtime.GOOS == "windows" {
		in, err := os.OpenFile("CONIN$", os.O_RDWR, 0)
		if err != nil {
			return err
		}
		defer in.Close()
		out, err := os.OpenFile("CONOUT$", os.O_WRONLY, 0)
		if err != nil {
			return err
		}
		defer out.Close()
		return f(in, out)
	} else if tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0); err == nil {
		defer tty.Close()
		return f(tty, tty)
	} else if term.IsTerminal(int(os.Stdin.Fd())) {
		return f(os.Stdin, os.Stdin)
	} else {
		return fmt.Errorf("standard input is not a terminal, and /dev/tty is not available: %v", err)
	}
}

// ReadSecret reads a value from the terminal with no echo. The prompt is ephemeral.
func ReadSecret(prompt string) (s []byte, err error) {
	err = WithTerminal(func(in, out *os.File) error {
		fmt.Fprintf(out, "%s ", prompt)
		defer ClearLine(out)
		s, err = term.ReadPassword(int(in.Fd()))
		return err
	})
	return
}

// readCharacter reads a single character from the terminal with no echo. The
// prompt is ephemeral.
func readCharacter(prompt string) (c byte, err error) {
	err = WithTerminal(func(in, out *os.File) error {
		fmt.Fprintf(out, "%s ", prompt)
		defer ClearLine(out)

		oldState, err := term.MakeRaw(int(in.Fd()))
		if err != nil {
			return err
		}
		defer term.Restore(int(in.Fd()), oldState)

		b := make([]byte, 1)
		if _, err := in.Read(b); err != nil {
			return err
		}

		c = b[0]
		return nil
	})
	return
}

var PluginTerminalUI = &plugin.ClientUI{
	DisplayMessage: func(name, message string) error {
		Printf("%s plugin: %s", name, message)
		return nil
	},
	RequestValue: func(name, message string, _ bool) (s string, err error) {
		defer func() {
			if err != nil {
				Warningf("could not read value for age-plugin-%s: %v", name, err)
			}
		}()
		secret, err := ReadSecret(message)
		if err != nil {
			return "", err
		}
		return string(secret), nil
	},
	Confirm: func(name, message, yes, no string) (choseYes bool, err error) {
		defer func() {
			if err != nil {
				Warningf("could not read value for age-plugin-%s: %v", name, err)
			}
		}()
		if no == "" {
			message += fmt.Sprintf(" (press enter for %q)", yes)
			_, err := ReadSecret(message)
			if err != nil {
				return false, err
			}
			return true, nil
		}
		message += fmt.Sprintf(" (press [1] for %q or [2] for %q)", yes, no)
		for {
			selection, err := readCharacter(message)
			if err != nil {
				return false, err
			}
			switch selection {
			case '1':
				return true, nil
			case '2':
				return false, nil
			case '\x03': // CTRL-C
				return false, errors.New("user cancelled prompt")
			default:
				Warningf("reading value for age-plugin-%s: invalid selection %q", name, selection)
			}
		}
	},
	WaitTimer: func(name string) {
		Printf("waiting on %s plugin...", name)
	},
}

type ReaderFunc func(p []byte) (n int, err error)

func (f ReaderFunc) Read(p []byte) (n int, err error) { return f(p) }
