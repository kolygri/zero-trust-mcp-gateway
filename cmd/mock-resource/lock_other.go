//go:build !darwin && !linux && !freebsd && !openbsd && !netbsd && !dragonfly

package main

import (
	"errors"
	"os"
)

func lockState(string) (*os.File, error) {
	return nil, errors.New("synthetic resource state locking requires a Unix host")
}
