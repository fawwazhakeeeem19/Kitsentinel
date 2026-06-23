package views

import (
	"context"
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/kitsentinel/cli/internal/engine/risk"
	"github.com/kitsentinel/cli/internal/models"
	"github.com/kitsentinel/cli/internal/storage"
	"github.com/kitsentinel/cli/internal/tui/styles"
)



type AssetView struct {
	store  *storage.Store
	assets []*models.Asset
	cursor int
	loaded bool
}

func NewAssetView(store *storage.Store) *AssetView { return &AssetView{store: store} }
func (v *AssetView) Init() tea.Cmd                { return nil }

func (v *AssetView) Load() {
	assets, err := v.store.ListAssets(context.Background())
	if err == nil {
		v.assets = assets
		v.loaded = true
	}
}

func (v *AssetView) View() string { return "" }

func (v *AssetView) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if !v.loaded {
		v.Load()
	}
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "up", "k":
			if v.cursor > 0 {
				v.cursor--
			}
		case "down", "j":
			if v.cursor < len(v.assets)-1 {
				v.cursor++
			}
		}
	}
	return v, nil
}

func (v *AssetView) Render(width, height int) string {
	if !v.loaded {
		v.Load()
	}
	title := styles.PanelTitle.Render(fmt.Sprintf("ASSET INVENTORY  (%d assets)", len(v.assets)))
	colW := []int{30, 12, 12, 8, 10, 10}
	header := renderRow([]string{"NAME", "TYPE", "ENVIRONMENT", "RISK", "LEVEL", "STATUS"}, colW, true)
	sep := styles.Separator(sumCols(colW, len(colW)))
	var rows []string
	maxRows := height - 8
	visibleStart := 0
	if v.cursor >= maxRows {
		visibleStart = v.cursor - maxRows + 1
	}
	for i, a := range v.assets {
		if i < visibleStart {
			continue
		}
		if i-visibleStart >= maxRows {
			break
		}
		riskColor := styles.RiskLevelColor(string(a.RiskLevel))
		cols := []string{
			trunc(a.Name, colW[0]-2),
			string(a.Type),
			string(a.Environment),
			fmt.Sprintf("%.0f", a.RiskScore),
			strings.ToUpper(string(a.RiskLevel)),
			string(a.Status),
		}
		selected := i == v.cursor
		style := styles.TableRow
		if selected {
			style = styles.TableRowSelected
		}
		rows = append(rows, style.Render(renderRowColored(cols, colW, riskColor, selected)))
	}
	content := lipgloss.JoinVertical(lipgloss.Left, title, header, sep, strings.Join(rows, "\n"))
	return styles.Panel.Width(width).Height(height - 2).Render(content)
}



type FindingView struct {
	store    *storage.Store
	findings []*models.Finding
	cursor   int
	loaded   bool
}

func NewFindingView(store *storage.Store) *FindingView { return &FindingView{store: store} }
func (v *FindingView) Init() tea.Cmd                  { return nil }
func (v *FindingView) View() string                   { return "" }

func (v *FindingView) Load() {
	findings, err := v.store.ListFindings(context.Background(), "")
	if err == nil {
		v.findings = findings
		v.loaded = true
	}
}

func (v *FindingView) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if !v.loaded {
		v.Load()
	}
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "up", "k":
			if v.cursor > 0 {
				v.cursor--
			}
		case "down", "j":
			if v.cursor < len(v.findings)-1 {
				v.cursor++
			}
		}
	}
	return v, nil
}

func (v *FindingView) Render(width, height int) string {
	if !v.loaded {
		v.Load()
	}
	crit, high, med, low := 0, 0, 0, 0
	for _, f := range v.findings {
		switch f.Severity {
		case models.SevCritical:
			crit++
		case models.SevHigh:
			high++
		case models.SevMedium:
			med++
		case models.SevLow:
			low++
		}
	}
	title := styles.PanelTitle.Render(fmt.Sprintf("FINDINGS (%d)  CRIT:%d  HIGH:%d  MED:%d  LOW:%d",
		len(v.findings), crit, high, med, low))
	colW := []int{28, 10, 16, 10, 12}
	header := renderRow([]string{"TITLE", "SEVERITY", "CATEGORY", "CVSS", "FIRST SEEN"}, colW, true)
	sep := styles.Separator(sumCols(colW, len(colW)))
	var rows []string
	maxRows := height - 8
	visibleStart := 0
	if v.cursor >= maxRows {
		visibleStart = v.cursor - maxRows + 1
	}
	for i, f := range v.findings {
		if i < visibleStart {
			continue
		}
		if i-visibleStart >= maxRows {
			break
		}
		sevColor := styles.SeverityColor(string(f.Severity))
		cols := []string{
			trunc(f.Title, colW[0]-2),
			strings.ToUpper(string(f.Severity)),
			string(f.Category),
			fmt.Sprintf("%.1f", f.CVSSScore),
			f.FirstSeenAt.Format("2006-01-02"),
		}
		selected := i == v.cursor
		style := styles.TableRow
		if selected {
			style = styles.TableRowSelected
		}
		rows = append(rows, style.Render(renderRowColored(cols, colW, sevColor, selected)))
	}
	if len(rows) == 0 {
		rows = []string{lipgloss.NewStyle().Foreground(styles.GreenColor).Padding(1, 0).
			Render("  ✓ No open findings")}
	}
	detail := ""
	if v.cursor < len(v.findings) {
		detail = v.renderDetail(v.findings[v.cursor], width)
	}
	content := lipgloss.JoinVertical(lipgloss.Left, title, header, sep,
		strings.Join(rows, "\n"), "", detail)
	return styles.Panel.Width(width).Height(height - 2).Render(content)
}

func (v *FindingView) renderDetail(f *models.Finding, width int) string {
	if f == nil {
		return ""
	}
	detailStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(styles.AccentColor).
		Padding(0, 1).
		Width(width - 4)
	content := lipgloss.JoinVertical(lipgloss.Left,
		styles.Code.Render("▸ "+f.Title),
		"",
		lipgloss.NewStyle().Foreground(styles.Text3Color).Render("Asset    : ")+
			lipgloss.NewStyle().Foreground(styles.Text2Color).Render(f.AssetName),
		lipgloss.NewStyle().Foreground(styles.Text3Color).Render("Category : ")+
			lipgloss.NewStyle().Foreground(styles.Text2Color).Render(string(f.Category)),
		lipgloss.NewStyle().Foreground(styles.Text3Color).Render("Fix      : ")+
			lipgloss.NewStyle().Foreground(styles.GreenColor).Render(trunc(f.Remediation, width-20)),
	)
	return detailStyle.Render(content)
}



type CertView struct {
	store  *storage.Store
	certs  []*models.Certificate
	cursor int
	loaded bool
}

func NewCertView(store *storage.Store) *CertView { return &CertView{store: store} }
func (v *CertView) Init() tea.Cmd               { return nil }
func (v *CertView) View() string                { return "" }

func (v *CertView) Load() {
	certs, err := v.store.ListCertificates(context.Background())
	if err == nil {
		v.certs = certs
		v.loaded = true
	}
}

func (v *CertView) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if !v.loaded {
		v.Load()
	}
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "up", "k":
			if v.cursor > 0 {
				v.cursor--
			}
		case "down", "j":
			if v.cursor < len(v.certs)-1 {
				v.cursor++
			}
		}
	}
	return v, nil
}

func (v *CertView) Render(width, height int) string {
	if !v.loaded {
		v.Load()
	}
	title := styles.PanelTitle.Render(fmt.Sprintf("CERTIFICATE CENTER  (%d monitored)", len(v.certs)))
	colW := []int{32, 18, 12, 6, 14, 12}
	header := renderRow([]string{"DOMAIN", "ISSUER", "KEY", "DAYS", "EXPIRES", "STATUS"}, colW, true)
	sep := styles.Separator(sumCols(colW, len(colW)))
	var rows []string
	maxRows := height - 8
	visibleStart := 0
	if v.cursor >= maxRows {
		visibleStart = v.cursor - maxRows + 1
	}
	for i, c := range v.certs {
		if i < visibleStart {
			continue
		}
		if i-visibleStart >= maxRows {
			break
		}
		var statusColor lipgloss.Color
		switch c.Status {
		case models.CertExpired:
			statusColor = styles.RedColor
		case models.CertExpiringSoon:
			statusColor = styles.OrangeColor
		case models.CertSelfSigned, models.CertWeakKey:
			statusColor = styles.YellowColor
		default:
			statusColor = styles.GreenColor
		}
		daysStr := fmt.Sprintf("%d", c.DaysUntilExpiry)
		if c.IsExpired {
			daysStr = "EXPIRED"
		}
		keyInfo := fmt.Sprintf("%s-%d", c.KeyType, c.KeyBits)
		cols := []string{
			trunc(c.Domain, colW[0]-2),
			trunc(c.Issuer, colW[1]-2),
			keyInfo,
			daysStr,
			c.NotAfter.Format("2006-01-02"),
			string(c.Status),
		}
		selected := i == v.cursor
		style := styles.TableRow
		if selected {
			style = styles.TableRowSelected
		}
		rows = append(rows, style.Render(renderRowColored(cols, colW, statusColor, selected)))
	}
	expiringCount := 0
	for _, c := range v.certs {
		if c.DaysUntilExpiry <= 30 && !c.IsExpired {
			expiringCount++
		}
	}
	warnMsg := ""
	if expiringCount > 0 {
		warnMsg = "\n  " + lipgloss.NewStyle().Foreground(styles.YellowColor).Bold(true).
			Render(fmt.Sprintf("⚠  %d certificate(s) expiring within 30 days", expiringCount))
	}
	content := lipgloss.JoinVertical(lipgloss.Left, title, header, sep,
		strings.Join(rows, "\n"), warnMsg)
	return styles.Panel.Width(width).Height(height - 2).Render(content)
}



type RiskView struct {
	store   *storage.Store
	riskEng *risk.Engine
	risks   []*models.RiskScore
	summary *models.OrgRiskSummary
	cursor  int
	loaded  bool
}

func NewRiskView(store *storage.Store, riskEng *risk.Engine) *RiskView {
	return &RiskView{store: store, riskEng: riskEng}
}
func (v *RiskView) Init() tea.Cmd { return nil }
func (v *RiskView) View() string  { return "" }

func (v *RiskView) Load() {
	summary, err := v.riskEng.CalculateAll(context.Background())
	if err == nil {
		v.summary = summary
		v.risks = summary.TopRisks
		v.loaded = true
	}
}

func (v *RiskView) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if !v.loaded {
		v.Load()
	}
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "up", "k":
			if v.cursor > 0 {
				v.cursor--
			}
		case "down", "j":
			if v.cursor < len(v.risks)-1 {
				v.cursor++
			}
		}
	}
	return v, nil
}

func (v *RiskView) Render(width, height int) string {
	if !v.loaded {
		v.Load()
	}
	leftW := width/2 - 2
	rightW := width - leftW - 4
	left := v.renderRiskTable(leftW, height)
	right := v.renderRiskSummary(rightW, height)
	return lipgloss.JoinHorizontal(lipgloss.Top, left, "  ", right)
}

func (v *RiskView) renderRiskTable(width, height int) string {
	title := styles.PanelTitle.Render("TOP RISK ASSETS")
	colW := []int{24, 8, 10, 10}
	header := renderRow([]string{"ASSET", "SCORE", "LEVEL", "TREND"}, colW, true)
	sep := styles.Separator(sumCols(colW, len(colW)))
	var rows []string
	for i, r := range v.risks {
		riskColor := styles.RiskLevelColor(string(r.RiskLevel))
		trend := "→"
		if r.Trend == "improving" {
			trend = "↓"
		}
		if r.Trend == "degrading" {
			trend = "↑"
		}
		cols := []string{
			trunc(r.AssetName, colW[0]-2),
			fmt.Sprintf("%.0f", r.OverallScore),
			strings.ToUpper(string(r.RiskLevel)),
			trend,
		}
		selected := i == v.cursor
		style := styles.TableRow
		if selected {
			style = styles.TableRowSelected
		}
		rows = append(rows, style.Render(renderRowColored(cols, colW, riskColor, selected)))
	}
	content := lipgloss.JoinVertical(lipgloss.Left, title, header, sep, strings.Join(rows, "\n"))
	return styles.Panel.Width(width).Height(height - 2).Render(content)
}

func (v *RiskView) renderRiskSummary(width, height int) string {
	if v.summary == nil {
		return styles.Panel.Width(width).Height(height-2).
			Render(styles.Muted.Render("No risk data.\nRun: kitsentinel risk"))
	}
	s := v.summary
	title := styles.PanelTitle.Render("ORG RISK SUMMARY")
	riskColor := styles.RiskLevelColor(string(s.RiskLevel))
	scoreDisplay := lipgloss.NewStyle().Foreground(riskColor).Bold(true).
		Render(fmt.Sprintf("%.0f", s.OverallScore)) +
		lipgloss.NewStyle().Foreground(styles.Text3Color).Render("/100  ") +
		lipgloss.NewStyle().Foreground(riskColor).Bold(true).Render(strings.ToUpper(string(s.RiskLevel)))
	bar := styles.ProgressBar(int(s.OverallScore), 100, width-6, riskColor)
	metrics := []struct{ k, v string }{
		{"Total Assets", fmt.Sprintf("%d", s.TotalAssets)},
		{"Critical Assets", fmt.Sprintf("%d", s.CriticalAssets)},
		{"Total Findings", fmt.Sprintf("%d", s.TotalFindings)},
		{"Critical", fmt.Sprintf("%d", s.CriticalFindings)},
		{"High", fmt.Sprintf("%d", s.HighFindings)},
		{"Exposures", fmt.Sprintf("%d", s.TotalExposures)},
		{"Expiring Certs", fmt.Sprintf("%d", s.ExpiringCerts)},
	}
	var metricLines []string
	for _, m := range metrics {
		metricLines = append(metricLines,
			lipgloss.NewStyle().Foreground(styles.Text3Color).Width(18).Render(m.k+":")+
				lipgloss.NewStyle().Foreground(styles.Text1Color).Bold(true).Render(m.v),
		)
	}
	content := lipgloss.JoinVertical(lipgloss.Left,
		title, scoreDisplay, bar, "",
		styles.Separator(width-4), "",
		strings.Join(metricLines, "\n"),
	)
	return styles.Panel.Width(width).Height(height - 2).Render(content)
}



func renderRow(cols []string, widths []int, header bool) string {
	style := styles.TableRow
	if header {
		style = styles.TableHeader
	}
	var parts []string
	for i, col := range cols {
		w := 10
		if i < len(widths) {
			w = widths[i]
		}
		parts = append(parts, style.Width(w).Render(trunc(col, w-1)))
	}
	return strings.Join(parts, " ")
}

func renderRowColored(cols []string, widths []int, color lipgloss.Color, selected bool) string {
	var parts []string
	for i, col := range cols {
		w := 10
		if i < len(widths) {
			w = widths[i]
		}
		var s lipgloss.Style
		if selected {
			s = styles.TableRowSelected.Width(w)
		} else if i == 3 || i == 4 {
			s = lipgloss.NewStyle().Foreground(color).Width(w)
		} else {
			s = styles.TableRow.Width(w)
		}
		parts = append(parts, s.Render(trunc(col, w-1)))
	}
	return strings.Join(parts, " ")
}

func sumCols(widths []int, n int) int {
	sum := 0
	for i := 0; i < n && i < len(widths); i++ {
		sum += widths[i] + 1
	}
	return sum
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}

var _ = time.Now // suppress unused import
