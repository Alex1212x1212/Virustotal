package config

import (
	"encoding/json"
	"os"
	"path/filepath"
)

type Config struct {
	APIKey        string `json:"api_key"`
	PublicAPIMode bool   `json:"public_api_mode"`
	Theme         string `json:"theme"`
	ColorTheme    string `json:"color_theme"`
	AutoOpenVT    bool   `json:"auto_open_vt"`
	Lang          string `json:"lang"`
}

type Manager struct {
	Config   Config
	FilePath string
}

func NewManager() *Manager {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	path := filepath.Join(home, ".vi_uploader_go.json")

	m := &Manager{
		FilePath: path,
	}
	m.Load()
	return m
}

func (m *Manager) Load() {
	m.setDefaults()
	data, err := os.ReadFile(m.FilePath)
	if err == nil {
		_ = json.Unmarshal(data, &m.Config)
	}
}

func (m *Manager) setDefaults() {
	m.Config = Config{
		APIKey:        "",
		PublicAPIMode: true,
		Theme:         "system",
		ColorTheme:    "blue",
		AutoOpenVT:    true,
		Lang:          "en",
	}
}

func (m *Manager) Save() error {
	data, err := json.MarshalIndent(m.Config, "", "  ")
	if err != nil {
		return err
	}
	tmp := m.FilePath + ".tmp"
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return err
	}
	return os.Rename(tmp, m.FilePath)
}
