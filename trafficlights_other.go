//go:build !darwin || server

package main

// adjustTrafficLightsAfterStartup is a no-op outside macOS.
func adjustTrafficLightsAfterStartup() {}
