//go:build !darwin || server

package main

// listLocalFonts is unavailable outside the macOS GUI build.
func listLocalFonts() []LocalFont { return nil }
