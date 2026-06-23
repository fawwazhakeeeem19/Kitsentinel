package analytics

import (
	"context"
	"fmt"
	"math"
	"sort"
	"time"

	"github.com/kitsentinel/cli/internal/models"
	"github.com/kitsentinel/cli/internal/storage"
)

type TrendPeriod string

const (
	Period24h TrendPeriod = "24h"
	Period7d  TrendPeriod = "7d"
	Period30d TrendPeriod = "30d"
	Period90d TrendPeriod = "90d"
	Period1y  TrendPeriod = "1y"
)

type TrendData struct {
	Labels           []string  `json:"labels"`
	RiskScores       []float64 `json:"risk_scores"`
	SecurityScores   []float64 `json:"security_scores"`
	TotalFindings    []int     `json:"total_findings"`
	NewFindings      []int     `json:"new_findings"`
	ResolvedFindings []int     `json:"resolved_findings"`
	Exposures        []int     `json:"exposures"`
}

type AnalyticsSummary struct {
	Period           TrendPeriod              `json:"period"`
	CurrentScore     float64                  `json:"current_score"`
	PreviousScore    float64                  `json:"previous_score"`
	ScoreDelta       float64                  `json:"score_delta"`
	Trend            string                   `json:"trend"`
	NewFindings      int                      `json:"new_findings"`
	ResolvedFindings int                      `json:"resolved_findings"`
	NewAssets        int                      `json:"new_assets"`
	MTTR             float64                  `json:"mttr_hours"`
	ByCategory       map[string]CategoryTrend `json:"by_category"`
	TimeSeriesData   *TrendData               `json:"time_series"`
	TopRiskyAssets   []AssetTrend             `json:"top_risky_assets"`
}

type CategoryTrend struct {
	Category string `json:"category"`
	Count    int    `json:"count"`
	Delta    int    `json:"delta"`
}

type AssetTrend struct {
	AssetName  string  `json:"asset_name"`
	RiskScore  float64 `json:"risk_score"`
	RiskLevel  string  `json:"risk_level"`
	Trend      string  `json:"trend"`
	TrendDelta float64 `json:"trend_delta"`
}

type Engine struct {
	store *storage.Store
}

func NewEngine(store *storage.Store) *Engine {
	return &Engine{store: store}
}

func (e *Engine) Analyze(ctx context.Context, period TrendPeriod) (*AnalyticsSummary, error) {
	days := periodToDays(period)
	metrics, err := e.store.ListHistoricalMetrics(ctx, days)
	if err != nil {
		return nil, fmt.Errorf("loading metrics: %w", err)
	}
	sort.Slice(metrics, func(i, j int) bool { return metrics[i].MetricDate < metrics[j].MetricDate })

	summary := &AnalyticsSummary{Period: period, ByCategory: map[string]CategoryTrend{}}

	stats, err := e.store.GetDashboardStats(ctx)
	if err != nil {
		return nil, err
	}

	risks, err := e.store.ListRisks(ctx)
	if err != nil {
		return nil, err
	}

	ts := &TrendData{}
	for _, m := range metrics {
		ts.Labels = append(ts.Labels, m.MetricDate)
		ts.RiskScores = append(ts.RiskScores, m.RiskScore)
		ts.SecurityScores = append(ts.SecurityScores, m.SecurityScore)
		ts.TotalFindings = append(ts.TotalFindings, m.TotalFindings)
		ts.NewFindings = append(ts.NewFindings, m.NewFindings)
		ts.ResolvedFindings = append(ts.ResolvedFindings, m.ResolvedFindings)
		ts.Exposures = append(ts.Exposures, m.TotalExposures)
	}
	summary.TimeSeriesData = ts

	if len(metrics) >= 2 {
		first := metrics[0]
		last := metrics[len(metrics)-1]
		summary.PreviousScore = first.SecurityScore
		summary.CurrentScore = last.SecurityScore
		summary.ScoreDelta = math.Round((last.SecurityScore-first.SecurityScore)*100) / 100
		summary.NewFindings = last.NewFindings
		summary.ResolvedFindings = last.ResolvedFindings
		summary.NewAssets = last.TotalAssets - first.TotalAssets
	} else {
		summary.CurrentScore = 100 - float64(stats.CriticalFindings)*8 - float64(stats.HighFindings)*4
		if summary.CurrentScore < 0 {
			summary.CurrentScore = 0
		}
		summary.NewFindings = stats.TotalFindings
	}

	switch {
	case summary.ScoreDelta > 2:
		summary.Trend = "improving"
	case summary.ScoreDelta < -2:
		summary.Trend = "degrading"
	default:
		summary.Trend = "stable"
	}

	summary.MTTR = e.calculateMTTR(ctx)

	sort.Slice(risks, func(i, j int) bool { return risks[i].OverallScore > risks[j].OverallScore })
	limit := 10
	if len(risks) < limit {
		limit = len(risks)
	}
	for _, r := range risks[:limit] {
		summary.TopRiskyAssets = append(summary.TopRiskyAssets, AssetTrend{
			AssetName: r.AssetName, RiskScore: r.OverallScore,
			RiskLevel: string(r.RiskLevel), Trend: r.Trend, TrendDelta: r.TrendDelta,
		})
	}

	e.snapshotMetrics(ctx, stats)
	return summary, nil
}

func (e *Engine) snapshotMetrics(ctx context.Context, stats *storage.DashboardStats) {
	today := time.Now().Format("2006-01-02")
	_ = e.store.UpsertHistoricalMetric(ctx, &models.HistoricalMetric{
		MetricDate: today, TotalAssets: stats.TotalAssets, ActiveAssets: stats.ActiveAssets,
		TotalFindings: stats.TotalFindings, CriticalFindings: stats.CriticalFindings,
		HighFindings: stats.HighFindings, MediumFindings: stats.MediumFindings,
		LowFindings: stats.LowFindings, TotalExposures: stats.TotalExposures,
		RiskScore: stats.OrgRiskScore, SecurityScore: 100 - stats.OrgRiskScore,
		ExpiringCerts: stats.ExpiringCerts, ScanCount: 1,
	})
}

func (e *Engine) calculateMTTR(ctx context.Context) float64 {
	sessions, _ := e.store.ListScanSessions(ctx, 100)
	totalHours, count := 0.0, 0
	for _, s := range sessions {
		if s.Status == models.ScanDone && s.StartedAt != nil && s.CompletedAt != nil {
			totalHours += s.CompletedAt.Sub(*s.StartedAt).Hours()
			count++
		}
	}
	if count == 0 {
		return 0
	}
	return math.Round((totalHours/float64(count))*100) / 100
}

func MiniSparkline(values []float64, width int) string {
	if len(values) == 0 {
		return ""
	}
	bars := []string{"▁", "▂", "▃", "▄", "▅", "▆", "▇", "█"}
	min, max := values[0], values[0]
	for _, v := range values {
		if v < min { min = v }
		if v > max { max = v }
	}
	step := len(values) / width
	if step < 1 { step = 1 }
	result := ""
	for i := 0; i < width && i*step < len(values); i++ {
		v := values[i*step]
		idx := 0
		if max != min {
			idx = int((v - min) / (max - min) * float64(len(bars)-1))
		}
		if idx >= len(bars) { idx = len(bars) - 1 }
		result += bars[idx]
	}
	return result
}

func RiskMiniBar(score float64, width int) string {
	filled := int(score / 100 * float64(width))
	bar := ""
	for i := 0; i < width; i++ {
		if i < filled { bar += "█" } else { bar += "░" }
	}
	return bar
}

func periodToDays(p TrendPeriod) int {
	switch p {
	case Period24h: return 1
	case Period7d: return 7
	case Period30d: return 30
	case Period90d: return 90
	case Period1y: return 365
	default: return 7
	}
}
