package ui

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/theme"
)

type compactTheme struct {
	fyne.Theme
}

func (c compactTheme) Size(name fyne.ThemeSizeName) float32 {
	switch name {
	case theme.SizeNameText:
		return 12
	case theme.SizeNameHeadingText:
		return 16
	case theme.SizeNameSubHeadingText:
		return 14
	case theme.SizeNameCaptionText:
		return 10
	case theme.SizeNamePadding:
		return 6
	}
	return c.Theme.Size(name)
}

func NewCompactTheme() fyne.Theme {
	return compactTheme{Theme: theme.LightTheme()}
}
