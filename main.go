package main

import (
	"embed"
	"flag"
	"log"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	"github.com/wailsapp/wails/v2/pkg/options/mac"
)

//go:embed all:frontend
var assets embed.FS

var (
	dbPath   = flag.String("db", "webssh.db", "path to SQLite database file")
	maxBody  = flag.Int64("maxbody", 50, "max upload body size in MB (0 = no limit)")
)

func main() {
	flag.Parse()

	if *maxBody < 0 {
		log.Fatal("-maxbody must be >= 0")
	}

	app := NewApp(*dbPath, *maxBody)

	err := wails.Run(&options.App{
		Title:             "WebSSH",
		Width:             1280,
		Height:            800,
		MinWidth:          900,
		MinHeight:         600,
		DisableResize:     false,
		StartHidden:       false,
		Frameless:         false,
		AssetServer: &assetserver.Options{
			Assets: assets,
		},
		BackgroundColour: &options.RGBA{R: 13, G: 17, B: 23, A: 255},
		OnStartup:        app.startup,
		OnShutdown:       app.shutdown,
		Bind: []interface{}{
			app,
		},
		Mac: &mac.Options{
			TitleBar:             mac.TitleBarDefault(),
			Appearance:           mac.NSAppearanceNameDarkAqua,
			WebviewIsTransparent: false,
			WindowIsTranslucent:  false,
		},
	})

	if err != nil {
		log.Fatal(err)
	}
}
