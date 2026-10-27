//go:build !darwin && !windows && !linux

package main

import (
	"github.com/wailsapp/wails/v3/pkg/application"
)

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
	return application.LinuxOptions{}
}
