//go:build linux

package main

import (
	"os"

	"github.com/wailsapp/wails/v2/pkg/options/linux"
	"github.com/wailsapp/wails/v2/pkg/options/mac"
	"github.com/wailsapp/wails/v2/pkg/options/windows"
)

func init() {
	os.Setenv("GTK_THEME", "Adwaita:dark")
	os.Setenv("GTK_THEME_VARIANT", "dark")
}

func linuxOptions() *linux.Options {
	return &linux.Options{
		ProgramName: "WebSSH",
	}
}

func macOptions() *mac.Options {
	return nil
}

func windowsOptions() *windows.Options {
	return nil
}
