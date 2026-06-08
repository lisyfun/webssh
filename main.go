package main

import (
	"embed"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
)

var lockFile string

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

	if runtime.GOOS == "linux" {
		singleInstanceOrExit()
	}

	app := NewApp(*dbPath, *maxBody)
	defer cleanupLock()

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
		Mac:     macOptions(),
		Windows: windowsOptions(),
		Linux:   linuxOptions(),
	})

	if err != nil {
		log.Fatal(err)
	}
}

func singleInstanceOrExit() {
	lockFile = fmt.Sprintf("/tmp/webssh-%d.lock", os.Getuid())
	data, err := os.ReadFile(lockFile)
	if err == nil {
		var pid int
		if _, err := fmt.Sscanf(string(data), "%d", &pid); err == nil {
			proc, err := os.FindProcess(pid)
			if err == nil && proc.Signal(syscall.Signal(0)) == nil {
				exec.Command("xdotool", "search", "--class", "WebSSH", "windowactivate").Run()
				os.Exit(0)
			}
		}
	}
	os.WriteFile(lockFile, []byte(fmt.Sprintf("%d\n", os.Getpid())), 0644)
}

func cleanupLock() {
	if lockFile != "" {
		os.Remove(lockFile)
	}
}
