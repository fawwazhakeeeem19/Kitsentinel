package report

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/template"
	"time"

	"github.com/kitsentinel/cli/internal/engine/analytics"
	"github.com/kitsentinel/cli/internal/engine/risk"
	"github.com/kitsentinel/cli/internal/models"
	"github.com/kitsentinel/cli/internal/storage"
)

type Format string

const (
	FormatText Format = "text"
	FormatJSON Format = "json"
	FormatHTML Format = "html"
	FormatCSV  Format = "csv"
)

type ReportData struct {
	GeneratedAt     time.Time                   `json:"generated_at"`
	Version         string                      `json:"version"`
	Period          string                      `json:"period"`
	ExecSummary     ExecutiveSummary            `json:"executive_summary"`
	Assets          []*models.Asset             `json:"assets"`
	Findings        []*models.Finding           `json:"findings"`
	Exposures       []*models.Exposure          `json:"exposures"`
	Certificates    []*models.Certificate       `json:"certificates"`
	Recommendations []*models.Recommendation   `json:"recommendations"`
	RiskSummary     *models.OrgRiskSummary      `json:"risk_summary"`
	Analytics       *analytics.AnalyticsSummary `json:"analytics"`
}

type ExecutiveSummary struct {
	SecurityScore  float64  `json:"security_score"`
	SecurityGrade  string   `json:"security_grade"`
	RiskLevel      string   `json:"risk_level"`
	TotalAssets    int      `json:"total_assets"`
	TotalFindings  int      `json:"total_findings"`
	CriticalIssues int      `json:"critical_issues"`
	HighIssues     int      `json:"high_issues"`
	ExposureCount  int      `json:"exposure_count"`
	ExpiringCerts  int      `json:"expiring_certs"`
	Trend          string   `json:"trend"`
	TopRemediation []string `json:"top_remediation"`
}

type Engine struct {
	store     *storage.Store
	riskEng   *risk.Engine
	analytics *analytics.Engine
	outputDir string
}

func NewEngine(store *storage.Store, riskEng *risk.Engine, analyticsEng *analytics.Engine, outputDir string) *Engine {
	_ = os.MkdirAll(outputDir, 0755)
	return &Engine{store: store, riskEng: riskEng, analytics: analyticsEng, outputDir: outputDir}
}

func (e *Engine) Generate(ctx context.Context, format Format, period analytics.TrendPeriod) (string, error) {
	data, err := e.collectData(ctx, period)
	if err != nil {
		return "", fmt.Errorf("collecting report data: %w", err)
	}
	timestamp := time.Now().Format("20060102-150405")
	ext := string(format)
	if format == FormatText { ext = "txt" }
	outPath := filepath.Join(e.outputDir, fmt.Sprintf("kitsentinel-report-%s.%s", timestamp, ext))

	switch format {
	case FormatJSON:
		err = e.writeJSON(outPath, data)
	case FormatHTML:
		err = e.writeHTML(outPath, data)
	case FormatCSV:
		err = e.writeCSV(outPath, data)
	default:
		err = e.writeText(outPath, data)
	}
	if err != nil {
		return "", err
	}
	return outPath, nil
}

func (e *Engine) collectData(ctx context.Context, period analytics.TrendPeriod) (*ReportData, error) {
	assets, _ := e.store.ListAssets(ctx)
	findings, _ := e.store.ListFindings(ctx, "")
	exposures, _ := e.store.ListExposures(ctx)
	certs, _ := e.store.ListCertificates(ctx)
	recs, _ := e.store.ListRecommendations(ctx)
	riskSummary, _ := e.riskEng.CalculateAll(ctx)
	analyticsData, _ := e.analytics.Analyze(ctx, period)
	secScore := e.riskEng.CalculateSecurityScore(ctx)

	topRem := []string{}
	for i, r := range recs {
		if i >= 5 { break }
		topRem = append(topRem, r.Title)
	}
	critical, high := 0, 0
	for _, f := range findings {
		if f.Severity == models.SevCritical { critical++ }
		if f.Severity == models.SevHigh { high++ }
	}
	expiringCerts := 0
	for _, c := range certs {
		if c.DaysUntilExpiry <= 30 && !c.IsExpired { expiringCerts++ }
	}
	trend := "stable"
	if analyticsData != nil { trend = analyticsData.Trend }
	riskLevel := "low"
	if riskSummary != nil { riskLevel = string(riskSummary.RiskLevel) }

	return &ReportData{
		GeneratedAt: time.Now(), Version: "1.0.0", Period: string(period),
		ExecSummary: ExecutiveSummary{
			SecurityScore: secScore, SecurityGrade: scoreGrade(secScore),
			RiskLevel: riskLevel, TotalAssets: len(assets),
			TotalFindings: len(findings), CriticalIssues: critical, HighIssues: high,
			ExposureCount: len(exposures), ExpiringCerts: expiringCerts,
			Trend: trend, TopRemediation: topRem,
		},
		Assets: assets, Findings: findings, Exposures: exposures,
		Certificates: certs, Recommendations: recs,
		RiskSummary: riskSummary, Analytics: analyticsData,
	}, nil
}

func (e *Engine) writeText(path string, data *ReportData) error {
	f, err := os.Create(path)
	if err != nil { return err }
	defer f.Close()
	w := func(format string, args ...interface{}) { fmt.Fprintf(f, format+"\n", args...) }
	sep := strings.Repeat("═", 72)
	thin := strings.Repeat("─", 72)
	w(sep)
	w("  KITSENTINEL SECURITY POSTURE REPORT")
	w("  Generated : %s", data.GeneratedAt.Format("2006-01-02 15:04:05"))
	w("  Period    : %s", data.Period)
	w(sep)
	w(""); w("  EXECUTIVE SUMMARY"); w(thin)
	w("  Security Score  : %.1f/100  [%s]", data.ExecSummary.SecurityScore, data.ExecSummary.SecurityGrade)
	w("  Risk Level      : %s", strings.ToUpper(data.ExecSummary.RiskLevel))
	w("  Trend           : %s", data.ExecSummary.Trend)
	w("  Total Assets    : %d", data.ExecSummary.TotalAssets)
	w("  Open Findings   : %d  (Critical: %d, High: %d)", data.ExecSummary.TotalFindings, data.ExecSummary.CriticalIssues, data.ExecSummary.HighIssues)
	w("  Exposures       : %d", data.ExecSummary.ExposureCount)
	w("  Expiring Certs  : %d", data.ExecSummary.ExpiringCerts)
	w(""); w("  TOP PRIORITY ACTIONS"); w(thin)
	for i, r := range data.ExecSummary.TopRemediation { w("  %d. %s", i+1, r) }
	w(""); w("  ASSET INVENTORY (%d)", len(data.Assets)); w(thin)
	w("  %-36s %-12s %-12s %s", "NAME", "TYPE", "ENVIRONMENT", "RISK")
	w("  " + strings.Repeat("-", 68))
	for _, a := range data.Assets {
		w("  %-36s %-12s %-12s %.1f [%s]", truncate(a.Name, 35), a.Type, a.Environment, a.RiskScore, strings.ToUpper(string(a.RiskLevel)))
	}
	w(""); w("  FINDINGS (%d open)", len(data.Findings)); w(thin)
	for _, fi := range data.Findings {
		w("  [%-8s] %s", strings.ToUpper(string(fi.Severity)), fi.Title)
		w("             Asset : %s | Category : %s", fi.AssetName, fi.Category)
		if fi.AffectedURL != "" { w("             URL   : %s", fi.AffectedURL) }
		w("             Fix   : %s", truncate(fi.Remediation, 60))
		w("")
	}
	if len(data.Exposures) > 0 {
		w("  EXPOSURES (%d active)", len(data.Exposures)); w(thin)
		for _, ex := range data.Exposures {
			w("  [%-8s] %s  →  %s", strings.ToUpper(string(ex.Severity)), ex.Title, ex.URL)
		}
		w("")
	}
	w("  CERTIFICATES (%d monitored)", len(data.Certificates)); w(thin)
	w("  %-40s %-12s %-6s %s", "DOMAIN", "STATUS", "DAYS", "EXPIRES")
	w("  " + strings.Repeat("-", 68))
	for _, c := range data.Certificates {
		w("  %-40s %-12s %-6d %s", truncate(c.Domain, 39), c.Status, c.DaysUntilExpiry, c.NotAfter.Format("2006-01-02"))
	}
	w(""); w("  RECOMMENDATIONS (%d)", len(data.Recommendations)); w(thin)
	for i, r := range data.Recommendations {
		if i >= 10 { break }
		w("  [%s] %s", priorityLabel(r.Priority), r.Title)
		w("       %s  |  Effort: %s", truncate(r.Explanation, 55), r.EstimatedEffort)
		w("")
	}
	w(sep); w("  END OF REPORT — KitSentinel v%s", data.Version); w(sep)
	return nil
}

func (e *Engine) writeJSON(path string, data *ReportData) error {
	f, err := os.Create(path)
	if err != nil { return err }
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(data)
}

var htmlTmpl = `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title>KitSentinel Report</title>
<style>body{background:#080c14;color:#e8f4fd;font-family:system-ui;font-size:13px;padding:24px}
h1{color:#00d4ff;font-size:20px;margin-bottom:4px}.meta{color:#4a6a8a;font-size:11px;margin-bottom:24px}
.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:28px}
.kpi{background:#0d1321;border:1px solid #1e3058;border-radius:8px;padding:16px}
.kv{font-size:26px;font-weight:700;font-family:monospace}.kl{font-size:10px;color:#4a6a8a;text-transform:uppercase;margin-top:2px}
h2{color:#4a6a8a;font-size:11px;text-transform:uppercase;letter-spacing:1px;border-bottom:1px solid #1e3058;padding-bottom:6px;margin:24px 0 12px}
table{width:100%;border-collapse:collapse}th{text-align:left;font-size:10px;text-transform:uppercase;color:#4a6a8a;padding:6px;border-bottom:1px solid #1e3058}
td{padding:7px;border-bottom:1px solid rgba(30,48,88,.3);color:#8ba3c7;font-size:12px}
.b{display:inline-block;padding:1px 7px;border-radius:3px;font-size:10px;font-weight:700}
.critical{color:#ff3366;background:rgba(255,51,102,.12)}.high{color:#ff6b35;background:rgba(255,107,53,.12)}
.medium{color:#ffd700;background:rgba(255,215,0,.1)}.low{color:#00d4ff;background:rgba(0,212,255,.1)}
.pass,.valid{color:#00ffaa;background:rgba(0,255,170,.1)}.expiring_soon{color:#ffd700;background:rgba(255,215,0,.1)}
.rec{background:#0d1321;border:1px solid #1e3058;border-left:3px solid;border-radius:6px;padding:10px;margin-bottom:8px}
.rec.p1_critical{border-left-color:#ff3366}.rec.p2_high{border-left-color:#ff6b35}.rec.p3_medium{border-left-color:#ffd700}
.rt{font-weight:600;color:#e8f4fd;margin-bottom:3px}.re{font-size:11px;color:#4a6a8a}</style></head>
<body><h1>▓▓ KITSENTINEL — SECURITY POSTURE REPORT</h1>
<div class="meta">Generated: {{.GeneratedAt.Format "2006-01-02 15:04:05"}} &nbsp;·&nbsp; Period: {{.Period}}</div>
<div class="grid">
<div class="kpi"><div class="kv" style="color:#00ffaa">{{printf "%.0f" .ExecSummary.SecurityScore}}</div><div class="kl">Security Score</div></div>
<div class="kpi"><div class="kv" style="color:#00d4ff">{{.ExecSummary.TotalAssets}}</div><div class="kl">Total Assets</div></div>
<div class="kpi"><div class="kv" style="color:#ff3366">{{.ExecSummary.TotalFindings}}</div><div class="kl">Open Findings</div></div>
<div class="kpi"><div class="kv" style="color:#ff6b35">{{.ExecSummary.ExposureCount}}</div><div class="kl">Exposures</div></div>
</div>
<h2>Findings</h2><table><thead><tr><th>Asset</th><th>Title</th><th>Severity</th><th>Category</th></tr></thead><tbody>
{{range .Findings}}<tr><td>{{.AssetName}}</td><td>{{.Title}}</td><td><span class="b {{.Severity}}">{{.Severity}}</span></td><td>{{.Category}}</td></tr>{{end}}
</tbody></table>
<h2>Certificates</h2><table><thead><tr><th>Domain</th><th>Days Left</th><th>Expires</th><th>Status</th></tr></thead><tbody>
{{range .Certificates}}<tr><td style="font-family:monospace">{{.Domain}}</td><td>{{.DaysUntilExpiry}}</td><td>{{.NotAfter.Format "2006-01-02"}}</td><td><span class="b {{.Status}}">{{.Status}}</span></td></tr>{{end}}
</tbody></table>
<h2>Recommendations</h2>
{{range .Recommendations}}<div class="rec {{.Priority}}"><div class="rt">{{.Title}}</div><div class="re">{{.Explanation}} — Effort: {{.EstimatedEffort}}</div></div>{{end}}
<div style="margin-top:32px;color:#4a6a8a;font-size:11px;text-align:center;font-family:monospace">KitSentinel v{{.Version}}</div>
</body></html>`

func (e *Engine) writeHTML(path string, data *ReportData) error {
	tmpl, err := template.New("r").Parse(htmlTmpl)
	if err != nil { return err }
	f, err := os.Create(path)
	if err != nil { return err }
	defer f.Close()
	return tmpl.Execute(f, data)
}

func (e *Engine) writeCSV(path string, data *ReportData) error {
	f, err := os.Create(path)
	if err != nil { return err }
	defer f.Close()
	fmt.Fprintln(f, "## FINDINGS")
	fmt.Fprintln(f, "asset_name,title,severity,category,status,affected_url")
	for _, fi := range data.Findings {
		fmt.Fprintf(f, "%s,%s,%s,%s,%s,%s\n", csvEsc(fi.AssetName), csvEsc(fi.Title), fi.Severity, fi.Category, fi.Status, csvEsc(fi.AffectedURL))
	}
	fmt.Fprintln(f, "\n## ASSETS")
	fmt.Fprintln(f, "name,type,environment,risk_score,risk_level")
	for _, a := range data.Assets {
		fmt.Fprintf(f, "%s,%s,%s,%.1f,%s\n", csvEsc(a.Name), a.Type, a.Environment, a.RiskScore, a.RiskLevel)
	}
	return nil
}

func truncate(s string, n int) string {
	if len(s) <= n { return s }
	return s[:n-3] + "..."
}
func csvEsc(s string) string {
	if strings.ContainsAny(s, `,"`) { return `"` + strings.ReplaceAll(s, `"`, `""`) + `"` }
	return s
}
func scoreGrade(s float64) string {
	switch { case s >= 90: return "A+"; case s >= 80: return "A"; case s >= 70: return "B"; case s >= 60: return "C"; case s >= 50: return "D"; default: return "F" }
}
func priorityLabel(p models.Priority) string {
	switch p {
	case models.PriorityP1Critical: return "P1 CRITICAL"
	case models.PriorityP2High: return "P2 HIGH"
	case models.PriorityP3Medium: return "P3 MEDIUM"
	default: return "P4 LOW"
	}
}
