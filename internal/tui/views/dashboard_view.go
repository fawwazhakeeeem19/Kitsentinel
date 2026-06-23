package views

import (
	"context"
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/kitsentinel/cli/internal/storage"
	"github.com/kitsentinel/cli/internal/tui/styles"
)


type DashboardView struct {
	store *storage.Store
	stats *storage.DashboardStats
}

func NewDashboardView(store *storage.Store) *DashboardView {
	return &DashboardView{store: store}
}

func (v *DashboardView) Init() tea.Cmd               { return nil }
func (v *DashboardView) View() string                { return "" }
func (v *DashboardView) SetStats(s *storage.DashboardStats) { v.stats = s }

func (v *DashboardView) Update(msg tea.Msg) (tea.Model, tea.Cmd) { return v, nil }

func (v *DashboardView) Render(width, height int, stats *storage.DashboardStats) string {
	if stats != nil {
		v.stats = stats
	}
	if v.stats == nil {
		return lipgloss.NewStyle().
			Foreground(styles.AccentColor).
			Width(width).Height(height).
			Align(lipgloss.Center, lipgloss.Center).
			Render("⟳ Loading dashboard data...")
	}

	secScore := 100.0 -
		float64(v.stats.CriticalFindings)*8 -
		float64(v.stats.HighFindings)*4 -
		float64(v.stats.MediumFindings)*1.5 -
		float64(v.stats.TotalExposures)*10 -
		float64(v.stats.ExpiringCerts)*5
	if secScore < 0 {
		secScore = 0
	}

	kpiRow := v.renderKPIRow(width, secScore)
	sevRow := v.renderSeveritySection(width)
	bottomRow := v.renderBottomSection(width)

	return lipgloss.JoinVertical(lipgloss.Left, "", kpiRow, "", sevRow, "", bottomRow)
}

func (v *DashboardView) renderKPIRow(width int, secScore float64) string {
	cardW := (width - 6) / 4
	scoreColor := styles.GreenColor
	if secScore < 80 { scoreColor = styles.YellowColor }
	if secScore < 60 { scoreColor = styles.OrangeColor }
	if secScore < 40 { scoreColor = styles.RedColor }

	kpi1 := v.kpiCard(cardW, fmt.Sprintf("%.0f", secScore), "Security Score", "Grade: "+styles.ScoreGrade(secScore), scoreColor)
	kpi2 := v.kpiCard(cardW, fmt.Sprintf("%d", v.stats.TotalAssets), "Total Assets", fmt.Sprintf("%d active", v.stats.ActiveAssets), styles.AccentColor)
	kpi3 := v.kpiCard(cardW, fmt.Sprintf("%d", v.stats.TotalFindings), "Open Findings", fmt.Sprintf("%d critical", v.stats.CriticalFindings), styles.RedColor)
	kpi4 := v.kpiCard(cardW, fmt.Sprintf("%d", v.stats.TotalExposures), "Exposures", fmt.Sprintf("%d certs expiring", v.stats.ExpiringCerts), styles.OrangeColor)

	return lipgloss.JoinHorizontal(lipgloss.Top, kpi1, "  ", kpi2, "  ", kpi3, "  ", kpi4)
}

func (v *DashboardView) kpiCard(width int, value, label, sub string, color lipgloss.Color) string {
	inner := lipgloss.JoinVertical(lipgloss.Left,
		lipgloss.NewStyle().Foreground(color).Bold(true).Render(value),
		lipgloss.NewStyle().Foreground(styles.Text2Color).Render(label),
		lipgloss.NewStyle().Foreground(styles.Text3Color).Render(sub),
	)
	return lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(styles.BorderColor).
		Padding(1, 2).
		Width(width).
		Render(inner)
}

func (v *DashboardView) renderSeveritySection(width int) string {
	leftW := width/2 - 2
	rightW := width - leftW - 4
	return lipgloss.JoinHorizontal(lipgloss.Top,
		v.renderSeverityBars(leftW),
		"  ",
		v.renderRiskGauge(rightW),
	)
}

func (v *DashboardView) renderSeverityBars(width int) string {
	title := styles.PanelTitle.Render("FINDINGS BY SEVERITY")
	total := v.stats.TotalFindings
	if total == 0 { total = 1 }
	rows := []struct {
		label string
		count int
		color lipgloss.Color
	}{
		{"CRITICAL", v.stats.CriticalFindings, styles.RedColor},
		{"HIGH    ", v.stats.HighFindings, styles.OrangeColor},
		{"MEDIUM  ", v.stats.MediumFindings, styles.YellowColor},
		{"LOW     ", v.stats.LowFindings, styles.AccentColor},
	}
	barWidth := width - 26
	var lines []string
	for _, r := range rows {
		bar := styles.ProgressBar(r.count, total, barWidth, r.color)
		line := lipgloss.JoinHorizontal(lipgloss.Center,
			lipgloss.NewStyle().Foreground(r.color).Width(10).Render(r.label),
			bar,
			lipgloss.NewStyle().Foreground(r.color).Bold(true).Width(6).Align(lipgloss.Right).
				Render(fmt.Sprintf("%d", r.count)),
		)
		lines = append(lines, line)
	}
	content := lipgloss.JoinVertical(lipgloss.Left, title, strings.Join(lines, "\n"))
	return styles.Panel.Width(width).Render(content)
}

func (v *DashboardView) renderRiskGauge(width int) string {
	title := styles.PanelTitle.Render("RISK OVERVIEW")
	orgRisk := v.stats.OrgRiskScore
	riskLevel := "NONE"
	riskColor := styles.GreenColor
	switch {
	case orgRisk >= 70: riskLevel, riskColor = "CRITICAL", styles.RedColor
	case orgRisk >= 50: riskLevel, riskColor = "HIGH", styles.OrangeColor
	case orgRisk >= 25: riskLevel, riskColor = "MEDIUM", styles.YellowColor
	case orgRisk > 0:   riskLevel, riskColor = "LOW", styles.AccentColor
	}
	riskDisplay := lipgloss.NewStyle().Foreground(riskColor).Bold(true).Render(fmt.Sprintf("%.0f", orgRisk))
	bar := styles.ProgressBar(int(orgRisk), 100, width-8, riskColor)
	riskLbl := lipgloss.NewStyle().Foreground(riskColor).Bold(true).Render(riskLevel)
	metrics := []struct{ k, v string }{
		{"Exposures", fmt.Sprintf("%d", v.stats.TotalExposures)},
		{"Cert Expiry", fmt.Sprintf("%d", v.stats.ExpiringCerts)},
	}
	var mLines []string
	for _, m := range metrics {
		mLines = append(mLines,
			lipgloss.NewStyle().Foreground(styles.Text3Color).Width(14).Render(m.k)+
				lipgloss.NewStyle().Foreground(styles.Text1Color).Bold(true).Render(m.v),
		)
	}
	content := lipgloss.JoinVertical(lipgloss.Left,
		title,
		riskDisplay+" / 100  "+riskLbl,
		bar, "",
		strings.Join(mLines, "\n"),
	)
	return styles.Panel.Width(width).Render(content)
}

func (v *DashboardView) renderBottomSection(width int) string {
	leftW := width/2 - 2
	rightW := width - leftW - 4
	return lipgloss.JoinHorizontal(lipgloss.Top,
		v.renderTopFindings(leftW),
		"  ",
		v.renderQuickActions(rightW),
	)
}

func (v *DashboardView) renderTopFindings(width int) string {
	title := styles.PanelTitle.Render("RECENT FINDINGS")
	findings, _ := v.store.ListFindings(context.Background(), "")
	var lines []string
	for i, f := range findings {
		if i >= 8 { break }
		sevColor := styles.SeverityColor(string(f.Severity))
		sev := "[" + strings.ToUpper(string(f.Severity)) + "]"
		badge := lipgloss.NewStyle().Foreground(sevColor).Width(10).Render(sev)
		t := lipgloss.NewStyle().Foreground(styles.Text2Color).Render(trunc(f.Title, width-14))
		lines = append(lines, badge+"  "+t)
	}
	if len(lines) == 0 {
		lines = []string{lipgloss.NewStyle().Foreground(styles.GreenColor).Render("✓ No open findings")}
	}
	content := lipgloss.JoinVertical(lipgloss.Left, title, strings.Join(lines, "\n"))
	return styles.Panel.Width(width).Render(content)
}

func (v *DashboardView) renderQuickActions(width int) string {
	title := styles.PanelTitle.Render("QUICK COMMANDS")
	cmds := []struct{ key, desc string }{
		{"kitsentinel inventory", "Discover & inventory assets"},
		{"kitsentinel assess", "Run security assessment"},
		{"kitsentinel risk", "Calculate risk scores"},
		{"kitsentinel analytics", "View trend analytics"},
		{"kitsentinel reports --html", "Generate HTML report"},
	}
	var lines []string
	for _, c := range cmds {
		lines = append(lines,
			lipgloss.NewStyle().Foreground(styles.AccentColor).Render("  $ "+c.key)+"\n"+
				lipgloss.NewStyle().Foreground(styles.Text3Color).Render("    "+c.desc),
		)
	}
	content := lipgloss.JoinVertical(lipgloss.Left, title, strings.Join(lines, "\n"))
	return styles.Panel.Width(width).Render(content)
}
