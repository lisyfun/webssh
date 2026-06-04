//go:build windows

package main

import (
	"github.com/wailsapp/wails/v2/pkg/options/mac"
	"github.com/wailsapp/wails/v2/pkg/options/windows"
)

func macOptions() *mac.Options {
	return nil
}

func windowsOptions() *windows.Options {
	return &windows.Options{
		WebviewIsTransparent:              false,
		WindowIsTranslucent:               false,
		BackdropType:                      windows.Mica,
		DisableWindowIcon:                 false,
		DisableFramelessWindowDecorations: false,
		IsZoomControlEnabled:              false,
		ZoomFactor:                        1.0,
		Theme:                             windows.Dark,
		CustomTheme: &windows.ThemeSettings{
			DarkModeTitleBar:           windows.RGB(26, 26, 30),
			DarkModeTitleBarInactive:   windows.RGB(22, 22, 26),
			DarkModeTitleText:          windows.RGB(230, 237, 243),
			DarkModeTitleTextInactive:  windows.RGB(130, 140, 150),
			DarkModeBorder:             windows.RGB(26, 26, 30),
			DarkModeBorderInactive:     windows.RGB(22, 22, 26),
			LightModeTitleBar:          windows.RGB(230, 237, 243),
			LightModeTitleBarInactive:  windows.RGB(220, 225, 232),
			LightModeTitleText:         windows.RGB(26, 26, 30),
			LightModeTitleTextInactive: windows.RGB(100, 110, 120),
			LightModeBorder:            windows.RGB(230, 237, 243),
			LightModeBorderInactive:    windows.RGB(200, 210, 220),
		},
	}
}
