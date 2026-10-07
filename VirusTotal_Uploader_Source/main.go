package main

import (
	_ "embed"
	"log"
	"net"
	"os"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"

	"github.com/alexander007/viuploader/config"
	"github.com/alexander007/viuploader/ui"
)

//go:embed icon.png
var iconData []byte

func main() {
	// Enforce single instance by binding to a local port
	listener, err := net.Listen("tcp", "127.0.0.1:48212")
	if err != nil {
		if len(os.Args) > 1 {
			// Send file path to existing instance
			conn, errDial := net.Dial("tcp", "127.0.0.1:48212")
			if errDial == nil {
				conn.Write([]byte(os.Args[1]))
				conn.Close()
			}
		}
		log.Println("Application is already running. Exiting.")
		os.Exit(0)
	}
	defer listener.Close()

	// Load configuration first to set Fyne language for standard dialogs
	cfg := config.NewManager()
	if cfg.Config.Lang != "" {
		os.Setenv("FYNE_LANG", cfg.Config.Lang)
	}

	// Setup Fyne app with ID for better system integration
	a := app.NewWithID("com.alexander007.viuploader")
	
	// Load Icon
	icon := fyne.NewStaticResource("icon.png", iconData)
	a.SetIcon(icon)

	// Create main window
	w := a.NewWindow("VirusTotal Uploader v3")
	
	// Apply compact theme
	a.Settings().SetTheme(ui.NewCompactTheme())
	
	// Default size
	w.Resize(fyne.NewSize(900, 600))
	
	// Build UI
	appUI := ui.NewAppUI(a, w, cfg)
	tabs := appUI.BuildTabs()
	
	w.SetContent(tabs)

	// Accept connections from other instances (Context Menu IPC)
	go func() {
		for {
			conn, errAcc := listener.Accept()
			if errAcc != nil {
				return
			}
			buf := make([]byte, 4096)
			n, errRead := conn.Read(buf)
			if errRead == nil && n > 0 {
				path := string(buf[:n])
				a.SendNotification(fyne.NewNotification("VirusTotal Uploader", "Loading file from Context Menu..."))
				w.Show()
				appUI.LoadFile(path)
			}
			conn.Close()
		}
	}()

	// Load file if passed via command line on cold start
	if len(os.Args) > 1 {
		appUI.LoadFile(os.Args[1])
	}

	// Set window properties for drag and drop
	w.SetOnDropped(func(pos fyne.Position, uris []fyne.URI) {
		if len(uris) > 0 {
			log.Println("File dropped:", uris[0].Path())
			appUI.LoadFile(uris[0].Path())
		}
	})

	log.Println("Starting VI Uploader Go")
	w.ShowAndRun()
}
