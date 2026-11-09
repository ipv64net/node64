//go:build !linux && !windows

package main

import (
	"fmt"
	"os"
	"runtime"
)

// install/uninstall gibt es vorerst nur unter Linux und Windows.
func install([]string) int {
	fmt.Fprintln(os.Stderr, "monitor64-agent: install is not supported on", runtime.GOOS, "yet")
	return 1
}

func uninstall([]string) int {
	fmt.Fprintln(os.Stderr, "monitor64-agent: uninstall is not supported on", runtime.GOOS, "yet")
	return 1
}
