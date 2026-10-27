//go:build windows

package main

import (
	"github.com/wailsapp/wails/v3/pkg/application"
)

// rgb packs an sRGB colour the way Wails expects it: 0x00BBGGRR.
func rgb(r, g, b uint8) *uint32 {
	v := uint32(r) | uint32(g)<<8 | uint32(b)<<16
	return &v
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
	return application.WindowsWindow{
		Theme: application.Dark,
		CustomTheme: application.ThemeSettings{
			DarkModeActive: &application.WindowTheme{
				TitleBarColour:  rgb(26, 26, 30),
				TitleTextColour: rgb(230, 237, 243),
				BorderColour:    rgb(26, 26, 30),
			},
			DarkModeInactive: &application.WindowTheme{
				TitleBarColour:  rgb(22, 22, 26),
				TitleTextColour: rgb(130, 140, 150),
				BorderColour:    rgb(22, 22, 26),
			},
			LightModeActive: &application.WindowTheme{
				TitleBarColour:  rgb(230, 237, 243),
				TitleTextColour: rgb(26, 26, 30),
				BorderColour:    rgb(230, 237, 243),
			},
			LightModeInactive: &application.WindowTheme{
				TitleBarColour:  rgb(220, 225, 232),
				TitleTextColour: rgb(100, 110, 120),
				BorderColour:    rgb(200, 210, 220),
			},
		},
	}
}

func linuxOptions() application.LinuxOptions {
	return application.LinuxOptions{}
}
