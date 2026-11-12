//go:build !linux

package privdrop

import "io/fs"

// owner gibt es nur unter Linux.
func owner(fs.FileInfo) (uid, gid int, ok bool) { return 0, 0, false }

// Drop gibt es nur unter Linux.
func Drop(string) {}
