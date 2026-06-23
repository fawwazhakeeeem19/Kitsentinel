package risk

import (
	"context"
	"math"

	"github.com/kitsentinel/cli/internal/models"
	"github.com/kitsentinel/cli/internal/storage"
)


type Engine struct {
	store *storage.Store
}

func NewEngine(store *storage.Store) *Engine {
	return &Engine{store: store}
}


func (e *Engine) CalculateAll(ctx context.Context) (*models.OrgRiskSummary, error) {
	assets, err := e.store.ListAssets(ctx)
	if err != nil {
		return nil, err
	}

	findings, err := e.store.ListFindings(ctx, "")
	if err != nil {
		return nil, err
	}

	exposures, err := e.store.ListExposures(ctx)
	if err != nil {
		return nil, err
	}


	findingsByAsset := map[string][]*models.Finding{}
	for _, f := range findings {
		findingsByAsset[f.AssetID] = append(findingsByAsset[f.AssetID], f)
	}

	exposuresByAsset := map[string][]*models.Exposure{}
	for _, ex := range exposures {
		exposuresByAsset[ex.AssetID] = append(exposuresByAsset[ex.AssetID], ex)
	}

	var topRisks []*models.RiskScore
	var totalRisk float64
	byCategory := map[string]int{}


	for _, f := range findings {
		byCategory[string(f.Category)]++
	}

	for _, a := range assets {
		aFindings := findingsByAsset[a.ID]
		aExposures := exposuresByAsset[a.ID]

		risk := e.calculateAssetRisk(a, aFindings, aExposures)


		a.RiskScore = risk.OverallScore
		a.RiskLevel = risk.RiskLevel
		_ = e.store.UpsertAsset(ctx, a)
		_ = e.store.UpsertRisk(ctx, risk)

		totalRisk += risk.OverallScore
		topRisks = append(topRisks, risk)
	}


	sortRisks(topRisks)
	if len(topRisks) > 10 {
		topRisks = topRisks[:10]
	}


	orgScore := 0.0
	if len(assets) > 0 {
		orgScore = totalRisk / float64(len(assets))
	}


	critical, high, medium, low := 0, 0, 0, 0
	for _, f := range findings {
		switch f.Severity {
		case models.SevCritical:
			critical++
		case models.SevHigh:
			high++
		case models.SevMedium:
			medium++
		case models.SevLow:
			low++
		}
	}

	criticalAssets := 0
	for _, a := range assets {
		if a.RiskLevel == models.RiskCritical || a.RiskLevel == models.RiskHigh {
			criticalAssets++
		}
	}

	expiringCerts, _ := e.store.CountExpiringCerts(ctx, 30)

	return &models.OrgRiskSummary{
		OverallScore:     orgScore,
		RiskLevel:        riskLevel(orgScore),
		TotalAssets:      len(assets),
		CriticalAssets:   criticalAssets,
		TotalFindings:    len(findings),
		CriticalFindings: critical,
		HighFindings:     high,
		MediumFindings:   medium,
		LowFindings:      low,
		TotalExposures:   len(exposures),
		ExpiringCerts:    expiringCerts,
		ByCategory:       byCategory,
		TopRisks:         topRisks,
	}, nil
}


func (e *Engine) calculateAssetRisk(a *models.Asset, findings []*models.Finding, exposures []*models.Exposure) *models.RiskScore {

	assetRisk := 0.0
	for _, f := range findings {
		switch f.Severity {
		case models.SevCritical:
			assetRisk += 25.0
		case models.SevHigh:
			assetRisk += 15.0
		case models.SevMedium:
			assetRisk += 7.0
		case models.SevLow:
			assetRisk += 2.0
		}
	}

	assetRisk = math.Min(assetRisk, 100)


	configRisk := 0.0
	catSet := map[models.Category]bool{}
	for _, f := range findings {
		catSet[f.Category] = true
	}

	configRisk = math.Min(float64(len(catSet))*12.0, 100)


	exposureRisk := 0.0
	for _, ex := range exposures {
		switch ex.Severity {
		case models.SevCritical:
			exposureRisk += 35.0
		case models.SevHigh:
			exposureRisk += 20.0
		case models.SevMedium:
			exposureRisk += 10.0
		case models.SevLow:
			exposureRisk += 4.0
		}
	}
	exposureRisk = math.Min(exposureRisk, 100)



	overall := (exposureRisk*0.40 + assetRisk*0.40 + configRisk*0.20)


	if a.IsCritical {
		overall = math.Min(overall*1.2, 100)
	}

	return &models.RiskScore{
		AssetID:                a.ID,
		AssetName:              a.Name,
		AssetRiskScore:         math.Round(assetRisk*100) / 100,
		ConfigurationRiskScore: math.Round(configRisk*100) / 100,
		ExposureRiskScore:      math.Round(exposureRisk*100) / 100,
		OverallScore:           math.Round(overall*100) / 100,
		RiskLevel:              riskLevel(overall),
		Trend:                  "stable", // Python engine will update this
	}
}


func (e *Engine) CalculateSecurityScore(ctx context.Context) float64 {
	stats, err := e.store.GetDashboardStats(ctx)
	if err != nil {
		return 0
	}
	score := 100.0

	score -= float64(stats.CriticalFindings) * 8
	score -= float64(stats.HighFindings) * 4
	score -= float64(stats.MediumFindings) * 2
	score -= float64(stats.LowFindings) * 0.5

	score -= float64(stats.TotalExposures) * 10

	score -= float64(stats.ExpiringCerts) * 5
	if score < 0 {
		score = 0
	}
	return math.Round(score*100) / 100
}

func riskLevel(score float64) models.RiskLevel {
	switch {
	case score >= 70:
		return models.RiskCritical
	case score >= 50:
		return models.RiskHigh
	case score >= 25:
		return models.RiskMedium
	case score > 0:
		return models.RiskLow
	default:
		return models.RiskNone
	}
}

func sortRisks(risks []*models.RiskScore) {
	for i := 1; i < len(risks); i++ {
		for j := i; j > 0 && risks[j].OverallScore > risks[j-1].OverallScore; j-- {
			risks[j], risks[j-1] = risks[j-1], risks[j]
		}
	}
}
