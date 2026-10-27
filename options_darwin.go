//go:build darwin

package main

import (
	"github.com/wailsapp/wails/v3/pkg/application"
)

func macOptions() application.MacOptions {
	return application.MacOptions{
		ApplicationShouldTerminateAfterLastWindowClosed: true,
	}
}

func macWindowOptions() application.MacWindow {
	return application.MacWindow{
		Appearance: application.NSAppearanceNameDarkAqua,
		TitleBar:   application.MacTitleBarHidden,
	}
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
