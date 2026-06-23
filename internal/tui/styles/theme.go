package styles

import "github.com/charmbracelet/lipgloss"

const (
	ColorAccent   = "#00d4ff"
	ColorAccent2  = "#00ffaa"
	ColorAccent3  = "#a855f7"
	ColorCritical = "#ff3366"
	ColorHigh     = "#ff6b35"
	ColorMedium   = "#ffd700"
	ColorLow      = "#00d4ff"
	ColorInfo     = "#8ba3c7"
	ColorBg0      = "#080c14"
	ColorBg1      = "#0d1321"
	ColorBg2      = "#111928"
	ColorBg3      = "#16213a"
	ColorBorder   = "#1e3058"
	ColorBorder2  = "#253870"
	ColorText1    = "#e8f4fd"
	ColorText2    = "#8ba3c7"
	ColorText3    = "#4a6a8a"
	ColorMuted    = "#2a4060"
	ColorGreen    = "#00ffaa"
	ColorRed      = "#ff3366"
	ColorYellow   = "#ffd700"
	ColorOrange   = "#ff6b35"
	ColorBlue     = "#00d4ff"
	ColorPurple   = "#a855f7"
)

var (
	AccentColor  = lipgloss.Color(ColorAccent)
	GreenColor   = lipgloss.Color(ColorGreen)
	RedColor     = lipgloss.Color(ColorRed)
	YellowColor  = lipgloss.Color(ColorYellow)
	OrangeColor  = lipgloss.Color(ColorOrange)
	PurpleColor  = lipgloss.Color(ColorPurple)
	Text1Color   = lipgloss.Color(ColorText1)
	Text2Color   = lipgloss.Color(ColorText2)
	Text3Color   = lipgloss.Color(ColorText3)
	BorderColor  = lipgloss.Color(ColorBorder)
	Border2Color = lipgloss.Color(ColorBorder2)
	Bg1Color     = lipgloss.Color(ColorBg1)
	Bg2Color     = lipgloss.Color(ColorBg2)
	Bg3Color     = lipgloss.Color(ColorBg3)
)

var AppTitle = lipgloss.NewStyle().Bold(true).Foreground(AccentColor).PaddingLeft(1)
var AppVersion = lipgloss.NewStyle().Foreground(Text3Color).PaddingLeft(1)
var Panel = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(BorderColor).Padding(0, 1)
var PanelActive = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(AccentColor).Padding(0, 1)
var PanelTitle = lipgloss.NewStyle().Foreground(Text3Color).Bold(true).PaddingBottom(1)
var Sidebar = lipgloss.NewStyle().Border(lipgloss.NormalBorder(), false, true, false, false).BorderForeground(BorderColor).PaddingRight(1)
var NavItem = lipgloss.NewStyle().Foreground(Text2Color).PaddingLeft(2)
var NavItemActive = lipgloss.NewStyle().Foreground(AccentColor).Bold(true).PaddingLeft(1).Border(lipgloss.NormalBorder(), false, false, false, true).BorderForeground(AccentColor)
var NavLabel = lipgloss.NewStyle().Foreground(Text3Color).PaddingLeft(2).PaddingTop(1)
var StatusBar = lipgloss.NewStyle().Background(lipgloss.Color(ColorBg3)).Foreground(Text2Color).PaddingLeft(1).PaddingRight(1)
var StatusOK = lipgloss.NewStyle().Foreground(GreenColor).Bold(true)
var StatusWarn = lipgloss.NewStyle().Foreground(YellowColor).Bold(true)
var StatusError = lipgloss.NewStyle().Foreground(RedColor).Bold(true)
var Bold = lipgloss.NewStyle().Bold(true).Foreground(Text1Color)
var Muted = lipgloss.NewStyle().Foreground(Text3Color)
var Code = lipgloss.NewStyle().Foreground(AccentColor)
var Label = lipgloss.NewStyle().Foreground(Text2Color)
var TableHeader = lipgloss.NewStyle().Foreground(Text3Color).Bold(true)
var TableRow = lipgloss.NewStyle().Foreground(Text2Color)
var TableRowSelected = lipgloss.NewStyle().Foreground(AccentColor).Bold(true).Background(lipgloss.Color("#0a1a30"))

func SeverityStyle(sev string) lipgloss.Style {
	base := lipgloss.NewStyle().Bold(true).Padding(0, 1)
	switch sev {
	case "critical":
		return base.Foreground(lipgloss.Color(ColorCritical)).Background(lipgloss.Color("#2a0010"))
	case "high":
		return base.Foreground(lipgloss.Color(ColorHigh)).Background(lipgloss.Color("#2a1000"))
	case "medium":
		return base.Foreground(lipgloss.Color(ColorMedium)).Background(lipgloss.Color("#2a2000"))
	case "low":
		return base.Foreground(lipgloss.Color(ColorLow)).Background(lipgloss.Color("#00152a"))
	default:
		return base.Foreground(Text2Color)
	}
}

func SeverityColor(sev string) lipgloss.Color {
	switch sev {
	case "critical":
		return lipgloss.Color(ColorCritical)
	case "high":
		return lipgloss.Color(ColorHigh)
	case "medium":
		return lipgloss.Color(ColorMedium)
	case "low":
		return lipgloss.Color(ColorLow)
	default:
		return Text2Color
	}
}

func ScoreStyle(score float64) lipgloss.Style {
	base := lipgloss.NewStyle().Bold(true)
	switch {
	case score >= 80:
		return base.Foreground(GreenColor)
	case score >= 60:
		return base.Foreground(YellowColor)
	case score >= 40:
		return base.Foreground(OrangeColor)
	default:
		return base.Foreground(RedColor)
	}
}

func ScoreGrade(score float64) string {
	switch {
	case score >= 90:
		return "A+"
	case score >= 80:
		return "A"
	case score >= 70:
		return "B"
	case score >= 60:
		return "C"
	case score >= 50:
		return "D"
	default:
		return "F"
	}
}

func RiskLevelColor(level string) lipgloss.Color {
	switch level {
	case "critical":
		return lipgloss.Color(ColorCritical)
	case "high":
		return lipgloss.Color(ColorHigh)
	case "medium":
		return lipgloss.Color(ColorMedium)
	case "low":
		return lipgloss.Color(ColorLow)
	default:
		return Text2Color
	}
}

func ProgressBar(current, max, width int, color lipgloss.Color) string {
	if max == 0 {
		return ""
	}
	filled := (current * width) / max
	if filled > width {
		filled = width
	}
	return lipgloss.NewStyle().Foreground(color).Render(repeatChar("█", filled)) +
		lipgloss.NewStyle().Foreground(lipgloss.Color(ColorMuted)).Render(repeatChar("░", width-filled))
}

func repeatChar(ch string, n int) string {
	out := ""
	for i := 0; i < n; i++ {
		out += ch
	}
	return out
}

func LogoSmall() string {
	return lipgloss.JoinHorizontal(lipgloss.Center,
		lipgloss.NewStyle().Foreground(AccentColor).Bold(true).Render("▓▓ KitSentinel ▓▓"),
		lipgloss.NewStyle().Foreground(Text3Color).Render("  Security Posture Management"),
	)
}

func Box(title, content string, active bool) string {
	style := Panel
	titleStyle := PanelTitle
	if active {
		style = PanelActive
		titleStyle = PanelTitle.Copy().Foreground(AccentColor)
	}
	return style.Render(titleStyle.Render(title) + "\n" + content)
}

func Separator(width int) string {
	return lipgloss.NewStyle().Foreground(BorderColor).Render(repeatChar("─", width))
}

func Tag(text string, color lipgloss.Color) string {
	return lipgloss.NewStyle().Foreground(color).Padding(0, 1).Render(text)
}
