package ui

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"image/color"
	"io"
	"net/url"
	"os"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"

	"golang.org/x/sys/windows/registry"

	"github.com/alexander007/viuploader/api"
	"github.com/alexander007/viuploader/config"
	"github.com/alexander007/viuploader/locales"
)

type AppUI struct {
	App    fyne.App
	Window fyne.Window
	Config *config.Manager
	API    *api.VirusTotalAPI
	
	currentFile string
	fileLabel   *widget.Entry
	hashLabel   *widget.Entry
	scanBtn     *widget.Button
	statusLabel *widget.Label
	progressBar *widget.ProgressBarInfinite
	reportLink  *widget.Hyperlink
	results     *widget.Table
	resultsData []ScanResult
}

type ScanResult struct {
	Engine  string
	Result  string
	Version string
}

func NewAppUI(a fyne.App, w fyne.Window, cfg *config.Manager) *AppUI {
	ui := &AppUI{
		App:         a,
		Window:      w,
		Config:      cfg,
		API:         api.NewVirusTotalAPI(cfg.Config.APIKey, cfg.Config.PublicAPIMode),
		resultsData: make([]ScanResult, 0),
	}
	return ui
}

func (ui *AppUI) setStatus(msg string) {
	if ui.statusLabel != nil {
		ui.statusLabel.SetText(msg)
	}
}

func (ui *AppUI) Tr(key string) string {
	return locales.Tr(ui.Config.Config.Lang, key)
}

func (ui *AppUI) BuildTabs() fyne.CanvasObject {
	ui.statusLabel = widget.NewLabel(ui.Tr("ready"))
	
	scanTab := container.NewTabItem(ui.Tr("tab_scan"), ui.buildScanTab())
	hashesTab := container.NewTabItem(ui.Tr("tab_hashes"), ui.buildHashesTab())
	settingsTab := container.NewTabItem(ui.Tr("tab_settings"), ui.buildSettingsTab())
	aboutTab := container.NewTabItem(ui.Tr("tab_about"), ui.buildAboutTab())

	tabs := container.NewAppTabs(scanTab, hashesTab, settingsTab, aboutTab)
	tabs.SetTabLocation(container.TabLocationTop)
	
	// Create the bottom status bar
	greenSquare := canvas.NewRectangle(color.NRGBA{R: 0, G: 200, B: 0, A: 255})
	greenSquare.SetMinSize(fyne.NewSize(10, 10))
	leftStatus := container.NewHBox(
		container.NewCenter(greenSquare),
		ui.statusLabel,
	)
	
	rightStatus := widget.NewLabelWithStyle(ui.Tr("copyright"), fyne.TextAlignTrailing, fyne.TextStyle{})
	rightStatus.Importance = widget.LowImportance
	
	bottomBar := container.NewPadded(container.NewBorder(nil, nil, leftStatus, rightStatus))
	
	// Add some padding around the tabs to match the screenshot's card-like appearance
	paddedTabs := container.NewPadded(tabs)

	return container.NewBorder(nil, bottomBar, nil, nil, paddedTabs)
}

func (ui *AppUI) buildScanTab() fyne.CanvasObject {
	ui.fileLabel = widget.NewEntry()
	ui.hashLabel = widget.NewEntry()
	
	browseBtn := widget.NewButton(ui.Tr("browse"), func() {
		fd := dialog.NewFileOpen(func(reader fyne.URIReadCloser, err error) {
			if err != nil || reader == nil {
				return
			}
			ui.LoadFile(reader.URI().Path())
		}, ui.Window)
		fd.Resize(fyne.NewSize(800, 500))
		fd.Show()
	})
	browseBtn.Importance = widget.HighImportance

	ui.scanBtn = widget.NewButton(ui.Tr("scan_upload"), func() {
		ui.runProcess(false)
	})
	ui.scanBtn.Importance = widget.HighImportance
	
	forceBtn := widget.NewButton(ui.Tr("force_reupload"), func() {
		ui.runProcess(true)
	})

	ui.progressBar = widget.NewProgressBarInfinite()
	ui.progressBar.Hide()

	ui.reportLink = widget.NewHyperlink(ui.Tr("vt_report_na"), nil)
	openVtBtn := widget.NewButton(ui.Tr("open_vt"), func() {
		if ui.reportLink.URL != nil {
			ui.App.OpenURL(ui.reportLink.URL)
		}
	})
	openVtBtn.Importance = widget.HighImportance
	
	ui.results = widget.NewTable(
		func() (int, int) { return len(ui.resultsData), 3 },
		func() fyne.CanvasObject { return widget.NewLabel("TemplateTextHereForWidth") },
		func(id widget.TableCellID, o fyne.CanvasObject) {
			label := o.(*widget.Label)
			label.Alignment = fyne.TextAlignCenter
			label.TextStyle = fyne.TextStyle{}
			res := ui.resultsData[id.Row]
			switch id.Col {
			case 0: label.SetText(res.Engine)
			case 1: label.SetText(res.Result)
			case 2: label.SetText(res.Version)
			}
		},
	)
	ui.results.SetColumnWidth(0, 250)
	ui.results.SetColumnWidth(1, 300)
	ui.results.SetColumnWidth(2, 250)

	header := container.NewGridWithColumns(3,
		container.NewCenter(widget.NewLabelWithStyle(ui.Tr("engine"), fyne.TextAlignCenter, fyne.TextStyle{Bold: true})),
		container.NewCenter(widget.NewLabelWithStyle(ui.Tr("result"), fyne.TextAlignCenter, fyne.TextStyle{Bold: true})),
		container.NewCenter(widget.NewLabelWithStyle(ui.Tr("version"), fyne.TextAlignCenter, fyne.TextStyle{Bold: true})),
	)
	headerWithSep := container.NewVBox(header, widget.NewSeparator())
	tableLayout := container.NewBorder(headerWithSep, nil, nil, nil, ui.results)
	tableBg := canvas.NewRectangle(color.NRGBA{R: 255, G: 255, B: 255, A: 255})
	tableBorder := canvas.NewRectangle(color.Transparent)
	tableBorder.StrokeColor = color.NRGBA{R: 160, G: 160, B: 160, A: 255}
	tableBorder.StrokeWidth = 1
	tableStack := container.NewStack(tableBg, tableLayout, tableBorder)

	dragDropRect := canvas.NewRectangle(color.NRGBA{R: 224, G: 224, B: 224, A: 255})
	dragDropLabel := widget.NewLabelWithStyle(ui.Tr("drop_hint")+"\n"+ui.Tr("drop_unavailable"), fyne.TextAlignCenter, fyne.TextStyle{})
	dragDropBox := container.NewStack(dragDropRect, container.NewPadded(dragDropLabel))

	top := container.NewVBox(
		widget.NewLabelWithStyle(ui.Tr("file_selection"), fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		container.NewBorder(nil, nil, nil, browseBtn, ui.fileLabel),
		dragDropBox,
		container.NewBorder(nil, nil, widget.NewLabel("SHA-256:"), nil, ui.hashLabel),
		widget.NewLabel(""), // Spacer
		widget.NewLabelWithStyle(ui.Tr("actions"), fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		container.NewGridWithColumns(2, ui.scanBtn, forceBtn),
		ui.progressBar,
		widget.NewLabel(""), // Spacer
		widget.NewLabelWithStyle(ui.Tr("scan_results"), fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		container.NewBorder(nil, nil, ui.reportLink, openVtBtn),
	)

	return container.NewPadded(container.NewBorder(top, nil, nil, nil, tableStack))
}

func (ui *AppUI) LoadFile(path string) {
	ui.currentFile = path
	ui.fileLabel.SetText(path)
	ui.setStatus(ui.Tr("calc_hash"))
	
	go func() {
		h, err := calcHash(path)
		if err != nil {
			ui.setStatus(ui.Tr("error"))
			dialog.ShowError(err, ui.Window)
			return
		}
		ui.hashLabel.SetText(h)
		ui.setStatus(ui.Tr("ready"))
	}()
}

func calcHash(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func (ui *AppUI) runProcess(force bool) {
	if ui.Config.Config.APIKey == "" {
		dialog.ShowInformation(ui.Tr("msg_missing_key"), ui.Tr("msg_enter_key"), ui.Window)
		return
	}
	if ui.currentFile == "" {
		dialog.ShowInformation(ui.Tr("msg_no_file"), ui.Tr("msg_select_file"), ui.Window)
		return
	}

	ui.scanBtn.Disable()
	ui.progressBar.Show()
	ui.setStatus(ui.Tr("scanning"))
	
	go func() {
		defer func() {
			ui.progressBar.Hide()
			ui.scanBtn.Enable()
		}()

		apiClient := api.NewVirusTotalAPI(ui.Config.Config.APIKey, ui.Config.Config.PublicAPIMode)
		
		var report map[string]interface{}
		var err error
		filehash := ui.hashLabel.Text

		if !force {
			ui.setStatus(ui.Tr("status_checking"))
			report, err = apiClient.GetFileReport(filehash)
			if err != nil {
				dialog.ShowError(err, ui.Window)
				ui.setStatus(ui.Tr("error"))
				return
			}
		}

		if report == nil || len(report) == 0 {
			ui.setStatus(ui.Tr("status_uploading"))
			analysisID, err := apiClient.UploadFile(ui.currentFile)
			if err != nil {
				dialog.ShowError(err, ui.Window)
				ui.setStatus(ui.Tr("error"))
				return
			}
			ui.setStatus(ui.Tr("status_waiting"))
			newHash, err := apiClient.WaitForAnalysis(analysisID, func(s string) {
				ui.setStatus(s)
			})
			if err != nil {
				dialog.ShowError(err, ui.Window)
				ui.setStatus(ui.Tr("error"))
				return
			}
			report, err = apiClient.GetFileReport(newHash)
			if err != nil {
				dialog.ShowError(err, ui.Window)
				ui.setStatus(ui.Tr("error"))
				return
			}
		}

		ui.displayResults(report)
	}()
}

func (ui *AppUI) displayResults(data map[string]interface{}) {
	ui.resultsData = make([]ScanResult, 0)
	
	if data == nil {
		ui.setStatus(ui.Tr("status_err_disp"))
		return
	}

	d, ok := data["data"].(map[string]interface{})
	if !ok { return }
	attrs, ok := d["attributes"].(map[string]interface{})
	if !ok { return }

	var hash string
	if h, ok := attrs["sha256"].(string); ok {
		hash = h
	} else if id, ok := d["id"].(string); ok {
		hash = id
	} else {
		hash = ui.hashLabel.Text
	}

	u, _ := url.Parse("https://www.virustotal.com/gui/file/" + hash)
	ui.reportLink.SetURL(u)
	ui.reportLink.SetText(u.String())

	results, ok := attrs["last_analysis_results"].(map[string]interface{})
	if !ok { return }

	mal := 0
	for engine, resRaw := range results {
		res, ok := resRaw.(map[string]interface{})
		if !ok { continue }
		
		cat, _ := res["category"].(string)
		txt, _ := res["result"].(string)
		if txt == "" {
			txt = ui.Tr("status_clean")
		}
		ver, _ := res["engine_version"].(string)

		if cat == "malicious" {
			mal++
		}
		ui.resultsData = append(ui.resultsData, ScanResult{Engine: engine, Result: txt, Version: ver})
	}

	ui.results.Refresh()
	summary := fmt.Sprintf("%d / %d", mal, len(results))
	if mal > 0 {
		ui.setStatus(fmt.Sprintf("%s (%s)", ui.Tr("status_malicious"), summary))
		dialog.ShowInformation(ui.Tr("status_malicious"), fmt.Sprintf(ui.Tr("msg_file_malic"), summary), ui.Window)
	} else {
		ui.setStatus(fmt.Sprintf("%s (%s)", ui.Tr("status_clean"), summary))
		dialog.ShowInformation(ui.Tr("status_clean"), fmt.Sprintf(ui.Tr("msg_file_clean"), summary), ui.Window)
	}
}

func (ui *AppUI) buildHashesTab() fyne.CanvasObject {
	hashEntry := widget.NewMultiLineEntry()
	hashEntry.SetPlaceHolder(ui.Tr("hashes_placeholder"))
	
	checkBtn := widget.NewButton(ui.Tr("check_hashes"), func() {
		// Implement hash checking logic
		dialog.ShowInformation(ui.Tr("msg_not_impl"), ui.Tr("msg_hash_bg"), ui.Window)
	})

	return container.NewBorder(
		widget.NewLabelWithStyle(ui.Tr("hash_checker"), fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		container.NewVBox(checkBtn),
		nil, nil,
		hashEntry,
	)
}

func (ui *AppUI) buildSettingsTab() fyne.CanvasObject {
	apiKeyEntry := widget.NewPasswordEntry()
	apiKeyEntry.SetText(ui.Config.Config.APIKey)
	
	publicModeCheck := widget.NewCheck(ui.Tr("public_mode"), nil)
	publicModeCheck.SetChecked(ui.Config.Config.PublicAPIMode)
	
	langSelect := widget.NewSelect([]string{"en", "ru"}, nil)
	langSelect.SetSelected(ui.Config.Config.Lang)
	
	saveBtn := widget.NewButton(ui.Tr("save_settings"), func() {
		ui.Config.Config.APIKey = apiKeyEntry.Text
		ui.Config.Config.PublicAPIMode = publicModeCheck.Checked
		ui.Config.Config.Lang = langSelect.Selected
		
		err := ui.Config.Save()
		if err != nil {
			dialog.ShowError(err, ui.Window)
		} else {
			dialog.ShowInformation(ui.Tr("msg_saved"), ui.Tr("msg_saved_succ"), ui.Window)
		}
	})

	contextAddBtn := widget.NewButton("Add to Context Menu", func() {
		if err := ui.addContextMenu(); err != nil {
			dialog.ShowError(err, ui.Window)
		} else {
			dialog.ShowInformation("Success", "Context menu added!", ui.Window)
		}
	})
	
	contextRemoveBtn := widget.NewButton("Remove Context Menu", func() {
		if err := ui.removeContextMenu(); err != nil {
			dialog.ShowError(err, ui.Window)
		} else {
			dialog.ShowInformation("Success", "Context menu removed!", ui.Window)
		}
	})

	form := container.NewVBox(
		widget.NewLabelWithStyle(ui.Tr("api_key"), fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		apiKeyEntry,
		publicModeCheck,
		widget.NewLabelWithStyle(ui.Tr("appearance"), fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		container.NewGridWithColumns(2, widget.NewLabel(ui.Tr("language")), langSelect),
		widget.NewLabelWithStyle("Integration", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		container.NewGridWithColumns(2, contextAddBtn, contextRemoveBtn),
		widget.NewLabel(""),
		saveBtn,
	)
	return form
}

func (ui *AppUI) addContextMenu() error {
	exePath, err := os.Executable()
	if err != nil {
		return err
	}
	
	k, _, err := registry.CreateKey(registry.CURRENT_USER, `Software\Classes\*\shell\viuploader`, registry.ALL_ACCESS)
	if err != nil {
		return err
	}
	defer k.Close()
	
	k.SetStringValue("", "Scan with VirusTotal Uploader")
	k.SetStringValue("Icon", exePath)
	
	kCmd, _, err := registry.CreateKey(k, `command`, registry.ALL_ACCESS)
	if err != nil {
		return err
	}
	defer kCmd.Close()
	
	return kCmd.SetStringValue("", fmt.Sprintf(`"%s" "%%1"`, exePath))
}

func (ui *AppUI) removeContextMenu() error {
	registry.DeleteKey(registry.CURRENT_USER, `Software\Classes\*\shell\viuploader\command`)
	return registry.DeleteKey(registry.CURRENT_USER, `Software\Classes\*\shell\viuploader`)
}

func (ui *AppUI) buildAboutTab() fyne.CanvasObject {
	return container.NewVBox(
		widget.NewLabelWithStyle("VirusTotal Uploader v3", fyne.TextAlignCenter, fyne.TextStyle{Bold: true}),
		widget.NewLabelWithStyle("VirusTotal Scanner", fyne.TextAlignCenter, fyne.TextStyle{}),
		widget.NewLabelWithStyle(ui.Tr("author")+": Alexander007 (Go Port)", fyne.TextAlignCenter, fyne.TextStyle{Bold: true}),
		widget.NewLabel(fmt.Sprintf("%s %s", ui.Tr("settings_path"), ui.Config.FilePath)),
	)
}
