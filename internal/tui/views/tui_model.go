package views

import (
	"context"
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/kitsentinel/cli/internal/engine/analytics"
	"github.com/kitsentinel/cli/internal/engine/risk"
	"github.com/kitsentinel/cli/internal/storage"
	"github.com/kitsentinel/cli/internal/tui/styles"
)

type NavEntry struct {
	Label  string
	Key    string
	Prefix string
}

var navEntries = []NavEntry{
	{"Dashboard", "dashboard", "⬡"},
	{"Inventory", "inventory", "◈"},
	{"Security", "security", "⊛"},
	{"Exposures", "exposures", "⚠"},
	{"Certificates", "certificates", "◉"},
	{"DNS", "dns", "⬡"},
	{"Risk", "risk", "◎"},
	{"Analytics", "analytics", "∿"},
	{"Recs", "recommendations", "◑"},
	{"Reports", "reports", "▤"},
	{"History", "history", "⊙"},
	{"Settings", "settings", "⊕"},
}

type TUIModel struct {
	store     *storage.Store
	riskEng   *risk.Engine
	analytics *analytics.Engine

	width, height int
	activeNav     int
	activeView    string

	dashView    *DashboardView
	assetView   *AssetView
	findingView *FindingView
	certView    *CertView
	riskView    *RiskView

	stats     *storage.DashboardStats
	loading   bool
	statusMsg string
}

func NewTUIModel(store *storage.Store, riskEng *risk.Engine, analyticsEng *analytics.Engine) *TUIModel {
	m := &TUIModel{
		store:      store,
		riskEng:    riskEng,
		analytics:  analyticsEng,
		activeNav:  0,
		activeView: "dashboard",
		loading:    true,
	}
	m.dashView = NewDashboardView(store)
	m.assetView = NewAssetView(store)
	m.findingView = NewFindingView(store)
	m.certView = NewCertView(store)
	m.riskView = NewRiskView(store, riskEng)
	return m
}

func (m *TUIModel) Init() tea.Cmd {
	return m.loadStats()
}

func (m *TUIModel) loadStats() tea.Cmd {
	return func() tea.Msg {
		stats, err := m.store.GetDashboardStats(context.Background())
		return statsMsg{stats: stats, err: err}
	}
}

type statsMsg struct {
	stats *storage.DashboardStats
	err   error
}

func (m *TUIModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height

	case statsMsg:
		m.loading = false
		m.stats = msg.stats
		if m.stats != nil {
			m.dashView.SetStats(m.stats)
		}

	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		case "?":
			m.statusMsg = "↑↓/jk navigate · Enter select · 1-9 quick nav · r refresh · q quit"
		case "r":
			m.loading = true
			cmds = append(cmds, m.loadStats())
		case "up", "k":
			if m.activeNav > 0 { m.switchNav(m.activeNav - 1) }
		case "down", "j":
			if m.activeNav < len(navEntries)-1 { m.switchNav(m.activeNav + 1) }
		case "1": m.switchNav(0)
		case "2": m.switchNav(1)
		case "3": m.switchNav(2)
		case "4": m.switchNav(3)
		case "5": m.switchNav(4)
		case "6": m.switchNav(5)
		case "7": m.switchNav(6)
		case "8": m.switchNav(7)
		case "9": m.switchNav(8)
		case "enter", " ":
			m.switchNav(m.activeNav)
		}
	}


	switch m.activeView {
	case "inventory":
		updated, cmd := m.assetView.Update(msg)
		m.assetView = updated.(*AssetView)
		cmds = append(cmds, cmd)
	case "security":
		updated, cmd := m.findingView.Update(msg)
		m.findingView = updated.(*FindingView)
		cmds = append(cmds, cmd)
	case "certificates":
		updated, cmd := m.certView.Update(msg)
		m.certView = updated.(*CertView)
		cmds = append(cmds, cmd)
	case "risk":
		updated, cmd := m.riskView.Update(msg)
		m.riskView = updated.(*RiskView)
		cmds = append(cmds, cmd)
	}

	return m, tea.Batch(cmds...)
}

func (m *TUIModel) switchNav(idx int) {
	if idx < 0 || idx >= len(navEntries) { return }
	m.activeNav = idx
	m.activeView = navEntries[idx].Key
	switch m.activeView {
	case "inventory":   m.assetView.Load()
	case "security":    m.findingView.Load()
	case "certificates": m.certView.Load()
	case "risk":        m.riskView.Load()
	}
}

func (m *TUIModel) View() string {
	if m.width == 0 {
		return "Initializing KitSentinel..."
	}
	sidebar := m.renderSidebar()
	header := m.renderHeader()
	content := m.renderContent()
	statusBar := m.renderStatusBar()
	main := lipgloss.JoinHorizontal(lipgloss.Top, sidebar, m.renderMainPanel(header, content))
	return lipgloss.JoinVertical(lipgloss.Left, main, statusBar)
}

func (m *TUIModel) renderSidebar() string {
	logoLine := lipgloss.NewStyle().Foreground(styles.AccentColor).Bold(true).PaddingLeft(1).Render("▓ KitSentinel")
	subLine := lipgloss.NewStyle().Foreground(styles.Text3Color).PaddingLeft(1).Render("Security Platform")
	logo := lipgloss.JoinVertical(lipgloss.Left, logoLine, subLine)
	logoBorder := lipgloss.NewStyle().
		Border(lipgloss.NormalBorder(), false, false, true, false).
		BorderForeground(styles.BorderColor).
		Padding(0, 0, 1, 0).Width(22).Render(logo)

	groups := []struct {
		label string
		items []int
	}{
		{"OVERVIEW", []int{0}},
		{"ASSETS", []int{1, 2}},
		{"SECURITY", []int{3, 4, 5, 6}},
		{"INTELLIGENCE", []int{7, 8, 9}},
		{"OUTPUT", []int{10, 11}},
	}

	var navLines []string
	for _, g := range groups {
		navLines = append(navLines,
			lipgloss.NewStyle().Foreground(styles.Text3Color).PaddingLeft(1).PaddingTop(1).Render(g.label))
		for _, i := range g.items {
			entry := navEntries[i]
			label := fmt.Sprintf("%s %s", entry.Prefix, entry.Label)
			if m.activeNav == i {
				navLines = append(navLines, styles.NavItemActive.Width(20).Render(label))
			} else {
				navLines = append(navLines, styles.NavItem.Width(20).Render(label))
			}
		}
	}

	userLine := lipgloss.NewStyle().Foreground(styles.Text3Color).PaddingLeft(1).PaddingTop(1).
		Render("─────────────────────\n● Security Admin\n  SOC Analyst")

	sidebar := lipgloss.JoinVertical(lipgloss.Left,
		logoBorder,
		lipgloss.JoinVertical(lipgloss.Left, navLines...),
		userLine,
	)

	return lipgloss.NewStyle().
		Border(lipgloss.NormalBorder(), false, true, false, false).
		BorderForeground(styles.BorderColor).
		Width(22).Height(m.height - 1).
		Render(sidebar)
}

func (m *TUIModel) renderHeader() string {
	entry := navEntries[m.activeNav]
	title := lipgloss.NewStyle().Foreground(styles.Text1Color).Bold(true).Render(entry.Label)
	var right []string
	if m.stats != nil {
		right = append(right, lipgloss.NewStyle().Foreground(styles.GreenColor).Render("● ACTIVE"))
	}
	if m.loading {
		right = append(right, lipgloss.NewStyle().Foreground(styles.AccentColor).Render("⟳ Loading..."))
	}
	right = append(right, lipgloss.NewStyle().Foreground(styles.Text3Color).Render("[r]Refresh [q]Quit [?]Help"))
	rightStr := strings.Join(right, "  ")
	contentWidth := m.width - 24
	leftW := contentWidth - lipgloss.Width(rightStr) - 2
	if leftW < 10 { leftW = 10 }
	header := lipgloss.JoinHorizontal(lipgloss.Center,
		lipgloss.NewStyle().Width(leftW).Render(title),
		rightStr,
	)
	return lipgloss.NewStyle().
		Border(lipgloss.NormalBorder(), false, false, true, false).
		BorderForeground(styles.BorderColor).
		Width(contentWidth).Padding(0, 1).Render(header)
}

func (m *TUIModel) renderContent() string {
	contentWidth := m.width - 26
	contentHeight := m.height - 5
	switch m.activeView {
	case "dashboard":
		return m.dashView.Render(contentWidth, contentHeight, m.stats)
	case "inventory":
		return m.assetView.Render(contentWidth, contentHeight)
	case "security":
		return m.findingView.Render(contentWidth, contentHeight)
	case "certificates":
		return m.certView.Render(contentWidth, contentHeight)
	case "risk":
		return m.riskView.Render(contentWidth, contentHeight)
	default:
		return lipgloss.NewStyle().
			Foreground(styles.Text3Color).
			Width(contentWidth).Height(contentHeight).
			Align(lipgloss.Center, lipgloss.Center).
			Render(fmt.Sprintf("[ %s ]\n\nRun: kitsentinel %s", strings.ToUpper(m.activeView), m.activeView))
	}
}

func (m *TUIModel) renderMainPanel(header, content string) string {
	return lipgloss.JoinVertical(lipgloss.Left, header, content)
}

func (m *TUIModel) renderStatusBar() string {
	left := lipgloss.NewStyle().Foreground(styles.AccentColor).Bold(true).Render("▓▓ KitSentinel v1.0.0")
	var statParts []string
	if m.stats != nil {
		statParts = []string{
			lipgloss.NewStyle().Foreground(styles.Text3Color).Render(fmt.Sprintf("Assets:%d", m.stats.TotalAssets)),
			lipgloss.NewStyle().Foreground(styles.RedColor).Render(fmt.Sprintf("Crit:%d", m.stats.CriticalFindings)),
			lipgloss.NewStyle().Foreground(styles.OrangeColor).Render(fmt.Sprintf("High:%d", m.stats.HighFindings)),
			lipgloss.NewStyle().Foreground(styles.YellowColor).Render(fmt.Sprintf("Certs⚠:%d", m.stats.ExpiringCerts)),
		}
	}
	msg := m.statusMsg
	if msg == "" {
		msg = "↑↓/jk navigate  ·  1-9 quick nav  ·  r refresh  ·  q quit"
	}
	right := lipgloss.NewStyle().Foreground(styles.Text3Color).Render(msg)
	center := strings.Join(statParts, "  │  ")
	avail := m.width - lipgloss.Width(left) - lipgloss.Width(right) - 4
	if avail < 0 { avail = 0 }
	bar := lipgloss.JoinHorizontal(lipgloss.Center,
		left,
		lipgloss.NewStyle().Width(avail).Align(lipgloss.Center).Render(center),
		right,
	)
	return lipgloss.NewStyle().
		Background(lipgloss.Color(styles.ColorBg3)).
		Width(m.width).Padding(0, 1).
		Render(bar)
}
