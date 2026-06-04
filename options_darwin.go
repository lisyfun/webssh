//go:build darwin

package main

import (
	"github.com/wailsapp/wails/v2/pkg/options/mac"
	"github.com/wailsapp/wails/v2/pkg/options/windows"
)

func macOptions() *mac.Options {
	return &mac.Options{
		TitleBar:             mac.TitleBarDefault(),
		Appearance:           mac.NSAppearanceNameDarkAqua,
		WebviewIsTransparent: false,
		WindowIsTranslucent:  false,
	}
}

func windowsOptions() *windows.Options {
	return nil
}
