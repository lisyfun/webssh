//go:build !darwin || server

package main

// applyWindowAppearance is a no-op outside macOS.
func applyWindowAppearance(bool, float64) {}
