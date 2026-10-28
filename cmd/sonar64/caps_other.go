//go:build !linux

package main

// raiseNetRaw gibt es nur unter Linux.
func raiseNetRaw() (bool, error) { return false, nil }
