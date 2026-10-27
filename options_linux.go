//go:build linux

package main

import (
	"os"

	"github.com/wailsapp/wails/v3/pkg/application"
)

func init() {
	os.Setenv("GTK_THEME", "Adwaita:dark")
	os.Setenv("GTK_THEME_VARIANT", "dark")
}

func macOptions() application.MacOptions {
	return application.MacOptions{}
}

func macWindowOptions() application.MacWindow {
	return application.MacWindow{}
}

func windowsOptions() application.WindowsOptions {
	return application.WindowsOptions{}
}

func windowsWindowOptions() application.WindowsWindow {
	return application.WindowsWindow{}
}

func linuxOptions() application.LinuxOptions {
	return application.LinuxOptions{
		ProgramName: "WebSSH",
	}
}
