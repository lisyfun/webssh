//go:build !darwin && !windows

package main

import (
	"github.com/wailsapp/wails/v2/pkg/options/mac"
	"github.com/wailsapp/wails/v2/pkg/options/windows"
)

func macOptions() *mac.Options {
	return nil
}

func windowsOptions() *windows.Options {
	return nil
}
