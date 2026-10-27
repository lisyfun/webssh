package main

import (
	"embed"
	"flag"
	"io/fs"
	"log"
	"os"
	"path/filepath"

	"github.com/wailsapp/wails/v3/pkg/application"
)

//go:embed all:frontend
var assets embed.FS

var (
	maxBody = flag.Int64("maxbody", 50, "max upload body size in MB (0 = no limit)")
)

func defaultDBPath() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "webssh.db"
	}
	p := filepath.Join(dir, "WebSSH", "webssh.db")
	os.MkdirAll(filepath.Dir(p), 0755)
	return p
}

func main() {
	dbPath := flag.String("db", defaultDBPath(), "path to SQLite database file")
	flag.Parse()

	if *maxBody < 0 {
		log.Fatal("-maxbody must be >= 0")
	}

	frontend, err := fs.Sub(assets, "frontend")
	if err != nil {
		log.Fatal(err)
	}

	app := NewApp(*dbPath, *maxBody)

	wailsApp := application.New(application.Options{
		Name:        "WebSSH",
		Description: "Web SSH terminal and SFTP browser",
		Assets: application.AssetOptions{
			Handler: application.AssetFileServerFS(frontend),
		},
		Services: []application.Service{
			application.NewService(app),
		},
		Mac:     macOptions(),
		Windows: windowsOptions(),
		Linux:   linuxOptions(),
		SingleInstance: &application.SingleInstanceOptions{
			UniqueID: "com.webssh.webssh",
			OnSecondInstanceLaunch: func(_ application.SecondInstanceData) {
				if w, ok := application.Get().Window.GetByName("main"); ok {
					w.Show()
					w.Focus()
				}
			},
		},
	})
	app.setApplication(wailsApp)

	wailsApp.Window.NewWithOptions(application.WebviewWindowOptions{
		Name:             "main",
		Title:            "WebSSH",
		Width:            1280,
		Height:           800,
		MinWidth:         900,
		MinHeight:        600,
		BackgroundColour: application.NewRGB(13, 17, 23),
		URL:              "/",
		Mac:              macWindowOptions(),
		Windows:          windowsWindowOptions(),
	})

	if err := wailsApp.Run(); err != nil {
		log.Fatal(err)
	}
}
