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

// tlsFilter is an io.Writer that discards TLS handshake error log lines.
// These are expected noise when using self-signed certificates.
type tlsFilter struct{}

func (tlsFilter) Write(p []byte) (int, error) {
	if len(p) > 0 && p[len(p)-1] == '\n' {
		p = p[:len(p)-1]
	}
	s := string(p)
	if strings.Contains(s, "TLS handshake error") || strings.Contains(s, "tls:") {
		return len(p), nil
	}
	return len(p), nil // discard all non-critical errors
}

func generateSelfSignedCert() tls.Certificate {
	key, err := ecdsa.GenerateKey(elliptic.P256(), crand.Reader)
	if err != nil {
		log.Fatal("generate key:", err)
	}
	sn, err := crand.Int(crand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		log.Fatal("generate serial:", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: sn,
		Subject:      pkix.Name{CommonName: "WebSSH"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1"), net.IPv4zero},
		DNSNames:     []string{"localhost"},
	}
	certDER, err := x509.CreateCertificate(crand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		log.Fatal("create cert:", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		log.Fatal("marshal key:", err)
	}
	cert, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
	)
	if err != nil {
		log.Fatal("load cert pair:", err)
	}
	return cert
}
