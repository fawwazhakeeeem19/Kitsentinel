package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/fatih/color"
	"github.com/kitsentinel/cli/internal/engine/analytics"
	"github.com/kitsentinel/cli/internal/engine/assessment"
	"github.com/kitsentinel/cli/internal/engine/recommendation"
	"github.com/kitsentinel/cli/internal/engine/report"
	"github.com/kitsentinel/cli/internal/engine/risk"
	"github.com/kitsentinel/cli/internal/models"
	"github.com/kitsentinel/cli/internal/storage"
	"github.com/kitsentinel/cli/internal/tui/views"
	"github.com/schollz/progressbar/v3"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	AppName    = "KitSentinel"
	AppVersion = "1.0.0"
	AppDesc    = "Security Posture Management Platform"
)

var (
	cfgFile    string
	dbPath     string
	targetFlag string
	quietFlag  bool
	jsonFlag   bool
)

var (
	cyanFn    = color.New(color.FgCyan, color.Bold).SprintFunc()
	greenFn   = color.New(color.FgGreen, color.Bold).SprintFunc()
	redFn     = color.New(color.FgRed, color.Bold).SprintFunc()
	yellowFn  = color.New(color.FgYellow, color.Bold).SprintFunc()
	magentaFn = color.New(color.FgMagenta, color.Bold).SprintFunc()
	dimFn     = color.New(color.Faint).SprintFunc()
	boldFn    = color.New(color.Bold).SprintFunc()
)

func printBanner() {
	fmt.Println()
	fmt.Println(cyanFn("  ██╗  ██╗██╗████████╗███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗"))
	fmt.Println(cyanFn("  ██║ ██╔╝██║╚══██╔══╝██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║"))
	fmt.Println(cyanFn("  █████╔╝ ██║   ██║   ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║"))
	fmt.Println(cyanFn("  ██╔═██╗ ██║   ██║   ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║"))
	fmt.Println(cyanFn("  ██║  ██╗██║   ██║   ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗"))
	fmt.Println(cyanFn("  ╚═╝  ╚═╝╚═╝   ╚═╝   ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝"))
	fmt.Println()
	fmt.Printf("  %s  %s  %s\n", cyanFn("Security Posture Management"), dimFn("v"+AppVersion), dimFn("github.com/kitsentinel/cli"))
	fmt.Println()
}

func printSep()              { fmt.Println(dimFn(strings.Repeat("─", 72))) }
func printHeader(title string) { printSep(); fmt.Printf("  %s\n", boldFn(title)); printSep() }
func info(f string, a ...interface{})  { fmt.Printf("  "+cyanFn("[*]")+" "+f+"\n", a...) }
func ok(f string, a ...interface{})    { fmt.Printf("  "+greenFn("[✓]")+" "+f+"\n", a...) }
func warn(f string, a ...interface{})  { fmt.Printf("  "+yellowFn("[!]")+" "+f+"\n", a...) }
func fail(f string, a ...interface{})  { fmt.Printf("  "+redFn("[✗]")+" "+f+"\n", a...) }
func kv(k, v string)                   { fmt.Printf("  %-22s %s\n", dimFn(k+":"), v) }

func openStore() (*storage.Store, error) {
	path := viper.GetString("database_path")
	if path == "" {
		home, _ := os.UserHomeDir()
		path = filepath.Join(home, ".kitsentinel", "sentinel.db")
	}
	_ = os.MkdirAll(filepath.Dir(path), 0755)
	return storage.New(path)
}



var rootCmd = &cobra.Command{
	Use:   "kitsentinel",
	Short: AppName + " — " + AppDesc,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		if cmd.Use != "tui" && !quietFlag {
			printBanner()
		}
	},
}



var initCmd = &cobra.Command{
	Use: "init", Short: "Initialize KitSentinel configuration",
	RunE: func(cmd *cobra.Command, args []string) error {
		home, _ := os.UserHomeDir()
		dir := filepath.Join(home, ".kitsentinel")
		_ = os.MkdirAll(dir, 0755)
		_ = os.MkdirAll(filepath.Join(dir, "reports"), 0755)
		cfgPath := filepath.Join(dir, "config.yaml")
		if _, err := os.Stat(cfgPath); err == nil {
			warn("Config already exists: %s", cfgPath)
			return nil
		}
		cfg := fmt.Sprintf("# KitSentinel Configuration — %s\ntargets:\n  # - example.com\ndatabase_path: %s\noutput_dir: %s\ntimeout_seconds: 30\nworker_count: 20\nuser_agent: \"KitSentinel/1.0 Security Scanner\"\nlog_level: info\n",
			time.Now().Format("2006-01-02"),
			filepath.Join(dir, "sentinel.db"),
			filepath.Join(dir, "reports"),
		)
		if err := os.WriteFile(cfgPath, []byte(cfg), 0644); err != nil {
			return err
		}
		ok("KitSentinel initialized!")
		kv("Config", cyanFn(cfgPath))
		kv("Database", cyanFn(filepath.Join(dir, "sentinel.db")))
		fmt.Println()
		info("Next: edit config, then run %s", cyanFn("kitsentinel inventory --target example.com"))
		fmt.Println()
		return nil
	},
}



var inventoryCmd = &cobra.Command{
	Use: "inventory", Short: "Discover and inventory assets",
	RunE: func(cmd *cobra.Command, args []string) error {
		targets := viper.GetStringSlice("targets")
		if targetFlag != "" {
			for _, t := range strings.Split(targetFlag, ",") {
				targets = append(targets, strings.TrimSpace(t))
			}
		}
		if len(targets) == 0 {
			return fmt.Errorf("no targets — use --target or add targets to config")
		}
		store, err := openStore()
		if err != nil { return err }
		defer store.Close()

		timeout := time.Duration(viper.GetInt("timeout_seconds")) * time.Second
		if timeout == 0 { timeout = 30 * time.Second }
		ua := viper.GetString("user_agent")
		if ua == "" { ua = "KitSentinel/1.0 Security Scanner" }

		scanner := assessment.NewScanner(timeout, ua)
		riskEng := risk.NewEngine(store)
		recEng := recommendation.NewEngine(store)

		printHeader("ASSET INVENTORY & SECURITY ASSESSMENT")
		info("Targets : %s", strings.Join(targets, ", "))
		fmt.Println()

		sess := &models.ScanSession{ScanType: models.ScanInventory, Status: models.ScanRunning, Target: strings.Join(targets, ",")}
		now := time.Now()
		sess.StartedAt = &now
		_ = store.CreateScanSession(context.Background(), sess)

		bar := progressbar.NewOptions(len(targets),
			progressbar.OptionSetDescription("  Scanning"),
			progressbar.OptionSetTheme(progressbar.Theme{Saucer: "█", SaucerPadding: "░", BarStart: "[", BarEnd: "]"}),
			progressbar.OptionShowCount(), progressbar.OptionSetWidth(40), progressbar.OptionClearOnFinish(),
		)

		totalFindings, totalExposures := 0, 0
		for _, target := range targets {
			target = strings.TrimSpace(target)
			if target == "" { continue }

			asset := &models.Asset{Name: target, Type: inferAssetType(target), Value: target,
				Environment: models.EnvProduction, Status: "active", IsMonitored: true}
			if err := store.UpsertAsset(context.Background(), asset); err != nil {
				_ = bar.Add(1); continue
			}

			result, err := scanner.Assess(context.Background(), asset)
			if err != nil { warn("Failed %s: %v", target, err); _ = bar.Add(1); continue }

			for _, f := range result.Findings { f.AssetID = asset.ID; _ = store.UpsertFinding(context.Background(), f); totalFindings++ }
			for _, e := range result.Exposures { e.AssetID = asset.ID; _ = store.UpsertExposure(context.Background(), e); totalExposures++ }
			if result.Cert != nil { result.Cert.AssetID = asset.ID; _ = store.UpsertCertificate(context.Background(), result.Cert) }
			if result.WebSec != nil { result.WebSec.AssetID = asset.ID; _ = store.UpsertWebSecurity(context.Background(), result.WebSec) }
			if result.DNSSec != nil { result.DNSSec.AssetID = asset.ID; _ = store.UpsertDNSSecurity(context.Background(), result.DNSSec) }
			_ = bar.Add(1)
		}
		_ = bar.Finish()

		info("Calculating risk...")
		orgRisk, _ := riskEng.CalculateAll(context.Background())
		info("Generating recommendations...")
		recs, _ := recEng.Generate(context.Background())

		done := time.Now()
		sess.Status = models.ScanDone; sess.CompletedAt = &done
		sess.FindingsCount = totalFindings; sess.ScannedAssets = len(targets)
		_ = store.UpdateScanSession(context.Background(), sess)

		fmt.Println()
		printHeader("RESULTS")
		kv("Assets Scanned", greenFn(fmt.Sprintf("%d", len(targets))))
		kv("Findings Found", redFn(fmt.Sprintf("%d", totalFindings)))
		kv("Exposures Found", redFn(fmt.Sprintf("%d", totalExposures)))
		kv("Recommendations", cyanFn(fmt.Sprintf("%d", len(recs))))
		if orgRisk != nil {
			rc := riskColorFn(string(orgRisk.RiskLevel))
			fmt.Println()
			kv("Org Risk Score", rc(fmt.Sprintf("%.1f/100", orgRisk.OverallScore)))
			kv("Risk Level", rc(strings.ToUpper(string(orgRisk.RiskLevel))))
		}
		fmt.Println()
		ok("Done. Run %s to open dashboard.", cyanFn("kitsentinel tui"))
		fmt.Println()
		return nil
	},
}



var assessCmd = &cobra.Command{
	Use: "assess", Short: "Run security posture assessment on all assets",
	RunE: func(cmd *cobra.Command, args []string) error {
		store, err := openStore()
		if err != nil { return err }
		defer store.Close()
		assets, _ := store.ListAssets(context.Background())
		if len(assets) == 0 { fail("No assets. Run %s first.", cyanFn("kitsentinel inventory --target <domain>")); return nil }
		scanner := assessment.NewScanner(30*time.Second, "KitSentinel/1.0")
		printHeader(fmt.Sprintf("SECURITY ASSESSMENT  (%d assets)", len(assets)))
		for _, asset := range assets {
			fmt.Printf("  %s %s\n", cyanFn("▸"), boldFn(asset.Name))
			result, err := scanner.Assess(context.Background(), asset)
			if err != nil { warn("  Failed: %v", err); continue }
			if result.WebSec != nil {
				gc := gradeColorFn(result.WebSec.Grade)
				fmt.Printf("    %-22s %s  (%.0f/100)\n", dimFn("Web Grade:"), gc(result.WebSec.Grade), result.WebSec.Score)
			}
			if result.Cert != nil {
				sc := certColorFn(string(result.Cert.Status))
				fmt.Printf("    %-22s %s  (%d days)\n", dimFn("Certificate:"), sc(string(result.Cert.Status)), result.Cert.DaysUntilExpiry)
			}
			if result.DNSSec != nil {
				fmt.Printf("    %-22s SPF:%-6s DMARC:%-6s\n", dimFn("Email Security:"),
					statusSym(string(result.DNSSec.SPFStatus)), statusSym(string(result.DNSSec.DMARCStatus)))
			}
			if len(result.Findings) > 0 { fmt.Printf("    %-22s %s\n", dimFn("Findings:"), redFn(fmt.Sprintf("%d new", len(result.Findings)))) }
			if len(result.Exposures) > 0 { fmt.Printf("    %-22s %s\n", dimFn("Exposures:"), redFn(fmt.Sprintf("%d detected!", len(result.Exposures)))) }
			for _, f := range result.Findings { _ = store.UpsertFinding(context.Background(), f) }
			for _, e := range result.Exposures { _ = store.UpsertExposure(context.Background(), e) }
			if result.Cert != nil { _ = store.UpsertCertificate(context.Background(), result.Cert) }
			if result.WebSec != nil { _ = store.UpsertWebSecurity(context.Background(), result.WebSec) }
			if result.DNSSec != nil { _ = store.UpsertDNSSecurity(context.Background(), result.DNSSec) }
			fmt.Println()
		}
		ok("Assessment complete.")
		return nil
	},
}



var riskCmd = &cobra.Command{
	Use: "risk", Short: "Calculate risk scores",
	RunE: func(cmd *cobra.Command, args []string) error {
		store, err := openStore()
		if err != nil { return err }
		defer store.Close()
		riskEng := risk.NewEngine(store)
		printHeader("RISK ENGINE")
		summary, err := riskEng.CalculateAll(context.Background())
		if err != nil { return err }
		rc := riskColorFn(string(summary.RiskLevel))
		fmt.Println()
		kv("Org Risk Score", rc(fmt.Sprintf("%.1f/100", summary.OverallScore)))
		kv("Risk Level", rc(strings.ToUpper(string(summary.RiskLevel))))
		kv("Security Score", greenFn(fmt.Sprintf("%.1f/100", riskEng.CalculateSecurityScore(context.Background()))))
		fmt.Println()
		kv("Total Assets", boldFn(fmt.Sprintf("%d", summary.TotalAssets)))
		kv("Critical Assets", redFn(fmt.Sprintf("%d", summary.CriticalAssets)))
		kv("Critical Findings", redFn(fmt.Sprintf("%d", summary.CriticalFindings)))
		kv("High Findings", yellowFn(fmt.Sprintf("%d", summary.HighFindings)))
		kv("Exposures", redFn(fmt.Sprintf("%d", summary.TotalExposures)))
		kv("Expiring Certs", yellowFn(fmt.Sprintf("%d", summary.ExpiringCerts)))
		if len(summary.TopRisks) > 0 {
			fmt.Println()
			printHeader("TOP RISK ASSETS")
			fmt.Printf("  %-30s %-8s %-10s %s\n", dimFn("ASSET"), dimFn("SCORE"), dimFn("LEVEL"), dimFn("TREND"))
			printSep()
			for _, r := range summary.TopRisks {
				rc2 := riskColorFn(string(r.RiskLevel))
				trend := dimFn("→ stable")
				if r.Trend == "improving" { trend = greenFn("↓ improving") }
				if r.Trend == "degrading" { trend = redFn("↑ degrading") }
				fmt.Printf("  %-30s %-8s %-10s %s\n",
					boldFn(trunc(r.AssetName, 29)), rc2(fmt.Sprintf("%.0f", r.OverallScore)),
					rc2(strings.ToUpper(string(r.RiskLevel))), trend)
			}
		}
		fmt.Println()
		return nil
	},
}



var analyticsPeriod string

var analyticsCmd = &cobra.Command{
	Use: "analytics", Short: "View trend analytics",
	RunE: func(cmd *cobra.Command, args []string) error {
		store, err := openStore()
		if err != nil { return err }
		defer store.Close()
		analyticsEng := analytics.NewEngine(store)
		printHeader(fmt.Sprintf("ANALYTICS — %s", strings.ToUpper(analyticsPeriod)))
		summary, err := analyticsEng.Analyze(context.Background(), analytics.TrendPeriod(analyticsPeriod))
		if err != nil { return err }

		trendFn := dimFn
		trendIcon := "→"
		switch summary.Trend {
		case "improving": trendFn = greenFn; trendIcon = "↓"
		case "degrading": trendFn = redFn; trendIcon = "↑"
		}
		fmt.Println()
		kv("Score (now)", greenFn(fmt.Sprintf("%.1f", summary.CurrentScore)))
		kv("Score (prev)", dimFn(fmt.Sprintf("%.1f", summary.PreviousScore)))
		kv("Delta", trendFn(fmt.Sprintf("%+.1f  %s %s", summary.ScoreDelta, trendIcon, summary.Trend)))
		kv("New Findings", redFn(fmt.Sprintf("%d", summary.NewFindings)))
		kv("Resolved", greenFn(fmt.Sprintf("%d", summary.ResolvedFindings)))
		kv("New Assets", cyanFn(fmt.Sprintf("%d", summary.NewAssets)))

		if summary.TimeSeriesData != nil && len(summary.TimeSeriesData.SecurityScores) > 1 {
			fmt.Println()
			printHeader("SECURITY SCORE TREND")
			spark := analytics.MiniSparkline(summary.TimeSeriesData.SecurityScores, 50)
			fmt.Printf("  %s %s %s\n",
				dimFn(fmt.Sprintf("%.0f", summary.PreviousScore)),
				cyanFn(spark),
				greenFn(fmt.Sprintf("%.0f", summary.CurrentScore)))
		}
		if len(summary.TopRiskyAssets) > 0 {
			fmt.Println()
			printHeader("RISK DISTRIBUTION")
			for _, a := range summary.TopRiskyAssets {
				bar := analytics.RiskMiniBar(a.RiskScore, 20)
				rc := riskColorFn(a.RiskLevel)
				fmt.Printf("  %-28s %s %s\n", trunc(a.AssetName, 27), rc(bar), rc(fmt.Sprintf("%.0f", a.RiskScore)))
			}
		}
		fmt.Println()
		return nil
	},
}



var (reportFormat, reportPeriod string)

var reportsCmd = &cobra.Command{
	Use: "reports", Short: "Generate security reports",
	RunE: func(cmd *cobra.Command, args []string) error {
		store, err := openStore()
		if err != nil { return err }
		defer store.Close()
		riskEng := risk.NewEngine(store)
		analyticsEng := analytics.NewEngine(store)
		outDir := viper.GetString("output_dir")
		if outDir == "" { outDir = "./reports" }
		reportEng := report.NewEngine(store, riskEng, analyticsEng, outDir)
		printHeader("REPORT GENERATION")
		info("Format: %s  Period: %s  Output: %s", boldFn(reportFormat), boldFn(reportPeriod), dimFn(outDir))
		fmt.Println()
		bar := progressbar.NewOptions(-1, progressbar.OptionSetDescription("  Generating"),
			progressbar.OptionSpinnerType(14), progressbar.OptionClearOnFinish())
		_ = bar.Add(1)
		outPath, err := reportEng.Generate(context.Background(), report.Format(reportFormat), analytics.TrendPeriod(reportPeriod))
		_ = bar.Finish()
		if err != nil { return err }
		fmt.Println()
		ok("Report generated!")
		kv("File", cyanFn(outPath))
		fmt.Println()
		return nil
	},
}



var certificatesCmd = &cobra.Command{
	Use: "certificates", Aliases: []string{"certs"}, Short: "Show SSL certificate status",
	RunE: func(cmd *cobra.Command, args []string) error {
		store, err := openStore()
		if err != nil { return err }
		defer store.Close()
		certs, _ := store.ListCertificates(context.Background())
		printHeader(fmt.Sprintf("CERTIFICATE CENTER  (%d monitored)", len(certs)))
		fmt.Printf("  %-34s %-18s %-6s %-12s %s\n", dimFn("DOMAIN"), dimFn("ISSUER"), dimFn("DAYS"), dimFn("EXPIRES"), dimFn("STATUS"))
		printSep()
		for _, c := range certs {
			sc := certColorFn(string(c.Status))
			days := fmt.Sprintf("%d", c.DaysUntilExpiry)
			if c.IsExpired { days = redFn("EXPIRED") }
			fmt.Printf("  %-34s %-18s %-6s %-12s %s\n",
				boldFn(trunc(c.Domain, 33)), dimFn(trunc(c.Issuer, 17)), days, c.NotAfter.Format("2006-01-02"), sc(string(c.Status)))
		}
		fmt.Println()
		return nil
	},
}



var assetsCmd = &cobra.Command{
	Use: "assets", Short: "List all assets",
	RunE: func(cmd *cobra.Command, args []string) error {
		store, err := openStore()
		if err != nil { return err }
		defer store.Close()
		assets, _ := store.ListAssets(context.Background())
		printHeader(fmt.Sprintf("ASSET INVENTORY  (%d assets)", len(assets)))
		fmt.Printf("  %-30s %-14s %-12s %-8s %s\n", dimFn("NAME"), dimFn("TYPE"), dimFn("ENVIRONMENT"), dimFn("RISK"), dimFn("LEVEL"))
		printSep()
		for _, a := range assets {
			rc := riskColorFn(string(a.RiskLevel))
			fmt.Printf("  %-30s %-14s %-12s %-8s %s\n",
				boldFn(trunc(a.Name, 29)), dimFn(string(a.Type)), string(a.Environment),
				rc(fmt.Sprintf("%.0f", a.RiskScore)), rc(strings.ToUpper(string(a.RiskLevel))))
		}
		fmt.Println()
		return nil
	},
}



var statusCmd = &cobra.Command{
	Use: "status", Short: "Show security posture at a glance",
	RunE: func(cmd *cobra.Command, args []string) error {
		store, err := openStore()
		if err != nil { return err }
		defer store.Close()
		stats, _ := store.GetDashboardStats(context.Background())
		riskEng := risk.NewEngine(store)
		secScore := riskEng.CalculateSecurityScore(context.Background())
		printHeader("SECURITY STATUS")
		sc := scoreColorFn(secScore)
		kv("Security Score", sc(fmt.Sprintf("%.1f/100  Grade: %s", secScore, scoreGrade(secScore))))
		fmt.Println()
		kv("Total Assets", boldFn(fmt.Sprintf("%d", stats.TotalAssets)))
		kv("Critical", redFn(fmt.Sprintf("%d", stats.CriticalFindings)))
		kv("High", yellowFn(fmt.Sprintf("%d", stats.HighFindings)))
		kv("Medium", fmt.Sprintf("%d", stats.MediumFindings))
		kv("Low", dimFn(fmt.Sprintf("%d", stats.LowFindings)))
		kv("Exposures", redFn(fmt.Sprintf("%d", stats.TotalExposures)))
		kv("Expiring Certs", yellowFn(fmt.Sprintf("%d", stats.ExpiringCerts)))
		fmt.Println()
		if stats.CriticalFindings > 0 { fail("Critical issues require immediate attention!") } else { ok("Run kitsentinel tui for full dashboard.") }
		fmt.Println()
		return nil
	},
}



var tuiCmd = &cobra.Command{
	Use: "tui", Short: "Launch interactive Terminal UI",
	RunE: func(cmd *cobra.Command, args []string) error {
		store, err := openStore()
		if err != nil { return err }
		defer store.Close()
		riskEng := risk.NewEngine(store)
		analyticsEng := analytics.NewEngine(store)
		model := views.NewTUIModel(store, riskEng, analyticsEng)
		p := tea.NewProgram(model, tea.WithAltScreen(), tea.WithMouseCellMotion())
		_, err = p.Run()
		return err
	},
}



var versionCmd = &cobra.Command{
	Use: "version", Short: "Show version",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("\n  %s  %s  %s\n\n", cyanFn(AppName), boldFn("v"+AppVersion), dimFn(AppDesc))
	},
}



func main() {
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file")
	rootCmd.PersistentFlags().StringVar(&dbPath, "db", "", "database path")
	rootCmd.PersistentFlags().BoolVarP(&quietFlag, "quiet", "q", false, "suppress banner")
	rootCmd.PersistentFlags().BoolVar(&jsonFlag, "json", false, "JSON output")
	rootCmd.PersistentFlags().StringVarP(&targetFlag, "target", "t", "", "scan targets (comma-separated)")

	analyticsPeriod = "7d"
	analyticsCmd.Flags().StringVarP(&analyticsPeriod, "period", "p", "7d", "24h|7d|30d|90d|1y")
	reportsCmd.Flags().StringVarP(&reportFormat, "format", "f", "text", "text|json|html|csv")
	reportsCmd.Flags().StringVarP(&reportPeriod, "period", "p", "7d", "24h|7d|30d|90d|1y")

	rootCmd.AddCommand(initCmd, inventoryCmd, assessCmd, riskCmd, analyticsCmd, reportsCmd, certificatesCmd, assetsCmd, tuiCmd, statusCmd, versionCmd)

	cobra.OnInitialize(func() {
		if cfgFile != "" {
			viper.SetConfigFile(cfgFile)
		} else {
			home, _ := os.UserHomeDir()
			viper.AddConfigPath(filepath.Join(home, ".kitsentinel"))
			viper.AddConfigPath(".")
			viper.SetConfigName("config")
			viper.SetConfigType("yaml")
		}
		viper.SetEnvPrefix("KITSENTINEL")
		viper.AutomaticEnv()
		_ = viper.ReadInConfig()
		if dbPath != "" { viper.Set("database_path", dbPath) }
	})

	if err := rootCmd.Execute(); err != nil { os.Exit(1) }
}



func inferAssetType(t string) models.AssetType {
	t = strings.ToLower(t)
	if strings.HasPrefix(t, "http") { return models.AssetWebApp }
	if strings.Contains(t, "api") { return models.AssetAPI }
	if strings.Contains(t, "mail") { return models.AssetMail }
	return models.AssetDomain
}
func riskColorFn(level string) func(...interface{}) string {
	switch level {
	case "critical": return redFn
	case "high": return yellowFn
	case "medium": return color.New(color.FgYellow).SprintFunc()
	case "low": return color.New(color.FgCyan).SprintFunc()
	default: return dimFn
	}
}
func scoreColorFn(score float64) func(...interface{}) string {
	if score >= 80 { return greenFn }
	if score >= 60 { return yellowFn }
	if score >= 40 { return color.New(color.FgYellow).SprintFunc() }
	return redFn
}
func gradeColorFn(grade string) func(...interface{}) string {
	switch grade {
	case "A+", "A": return greenFn
	case "B": return cyanFn
	case "C", "D": return yellowFn
	default: return redFn
	}
}
func certColorFn(status string) func(...interface{}) string {
	switch status {
	case "valid": return greenFn
	case "expiring_soon": return yellowFn
	case "expired": return redFn
	default: return magentaFn
	}
}
func statusSym(status string) string {
	switch status {
	case "pass": return greenFn("PASS")
	case "fail": return redFn("FAIL")
	case "warning": return yellowFn("WARN")
	default: return dimFn("N/A ")
	}
}
func scoreGrade(s float64) string {
	switch { case s >= 90: return "A+"; case s >= 80: return "A"; case s >= 70: return "B"; case s >= 60: return "C"; case s >= 50: return "D"; default: return "F" }
}
func trunc(s string, n int) string {
	if len(s) <= n { return s }
	return s[:n-3] + "..."
}
