//go:build !windows

package main

import (
	"fmt"
	"os"
)

// tray: das Symbol im Infobereich gibt es nur unter Windows.
func tray([]string) int {
	fmt.Fprintln(os.Stderr, "monitor64-agent: tray is only available on Windows")
	return 2
}
