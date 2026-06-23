package storage

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/kitsentinel/cli/internal/models"
	_ "github.com/mattn/go-sqlite3"
)

type Store struct {
	db *sqlx.DB
}


func New(path string) (*Store, error) {
	db, err := sqlx.Open("sqlite3", path+"?_journal=WAL&_timeout=5000&_foreign_keys=on")
	if err != nil {
		return nil, fmt.Errorf("opening database: %w", err)
	}
	db.SetMaxOpenConns(1) // SQLite: single writer
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		return nil, fmt.Errorf("running migrations: %w", err)
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }



func (s *Store) migrate() error {
	schema := `
CREATE TABLE IF NOT EXISTS assets (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    type TEXT NOT NULL,
    value TEXT NOT NULL,
    environment TEXT NOT NULL DEFAULT 'unknown',
    status TEXT NOT NULL DEFAULT 'active',
    owner TEXT DEFAULT '',
    team TEXT DEFAULT '',
    tags TEXT DEFAULT '',
    risk_score REAL NOT NULL DEFAULT 0,
    risk_level TEXT NOT NULL DEFAULT 'none',
    is_monitored INTEGER NOT NULL DEFAULT 1,
    is_critical INTEGER NOT NULL DEFAULT 0,
    first_seen_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    asset_id TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    asset_name TEXT NOT NULL DEFAULT '',
    title TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    severity TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open',
    category TEXT NOT NULL,
    affected_url TEXT DEFAULT '',
    evidence TEXT DEFAULT '',
    impact TEXT DEFAULT '',
    remediation TEXT DEFAULT '',
    references TEXT DEFAULT '',
    cvss_score REAL NOT NULL DEFAULT 0,
    confidence REAL NOT NULL DEFAULT 100,
    hash TEXT UNIQUE,
    first_seen_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    resolved_at DATETIME,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_findings_asset ON findings(asset_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);

CREATE TABLE IF NOT EXISTS certificates (
    id TEXT PRIMARY KEY,
    asset_id TEXT REFERENCES assets(id) ON DELETE SET NULL,
    domain TEXT NOT NULL,
    common_name TEXT DEFAULT '',
    issuer TEXT DEFAULT '',
    key_type TEXT DEFAULT '',
    key_bits INTEGER DEFAULT 0,
    signature_algo TEXT DEFAULT '',
    tls_version TEXT DEFAULT '',
    not_before DATETIME,
    not_after DATETIME,
    days_until_expiry INTEGER DEFAULT 0,
    is_expired INTEGER DEFAULT 0,
    is_self_signed INTEGER DEFAULT 0,
    is_wildcard INTEGER DEFAULT 0,
    chain_valid INTEGER DEFAULT 1,
    status TEXT NOT NULL DEFAULT 'valid',
    fingerprint TEXT DEFAULT '',
    serial_number TEXT DEFAULT '',
    sans TEXT DEFAULT '',
    last_checked_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_certs_domain ON certificates(domain);
CREATE INDEX IF NOT EXISTS idx_certs_status ON certificates(status);

CREATE TABLE IF NOT EXISTS dns_security (
    id TEXT PRIMARY KEY,
    asset_id TEXT REFERENCES assets(id) ON DELETE CASCADE,
    domain TEXT NOT NULL,
    spf_status TEXT NOT NULL DEFAULT 'not_configured',
    spf_record TEXT DEFAULT '',
    dkim_status TEXT NOT NULL DEFAULT 'not_configured',
    dmarc_status TEXT NOT NULL DEFAULT 'not_configured',
    dmarc_record TEXT DEFAULT '',
    dmarc_policy TEXT DEFAULT '',
    mta_sts_status TEXT NOT NULL DEFAULT 'not_configured',
    dnssec_status TEXT NOT NULL DEFAULT 'not_configured',
    overall_score REAL NOT NULL DEFAULT 0,
    analyzed_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS web_security (
    id TEXT PRIMARY KEY,
    asset_id TEXT REFERENCES assets(id) ON DELETE CASCADE,
    url TEXT NOT NULL,
    grade TEXT NOT NULL DEFAULT 'unknown',
    score REAL NOT NULL DEFAULT 0,
    tls_version TEXT DEFAULT '',
    has_hsts INTEGER DEFAULT 0,
    has_csp INTEGER DEFAULT 0,
    has_x_frame_options INTEGER DEFAULT 0,
    has_x_content_type_options INTEGER DEFAULT 0,
    has_referrer_policy INTEGER DEFAULT 0,
    has_permissions_policy INTEGER DEFAULT 0,
    cookies_secure INTEGER DEFAULT 0,
    cookies_httponly INTEGER DEFAULT 0,
    http_to_https INTEGER DEFAULT 0,
    server_version_disclosed INTEGER DEFAULT 0,
    server_header TEXT DEFAULT '',
    issues TEXT DEFAULT '[]',
    analyzed_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS exposures (
    id TEXT PRIMARY KEY,
    asset_id TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    asset_name TEXT NOT NULL DEFAULT '',
    exposure_type TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT DEFAULT '',
    url TEXT NOT NULL,
    severity TEXT NOT NULL,
    confidence REAL NOT NULL DEFAULT 80,
    business_impact TEXT DEFAULT '',
    is_active INTEGER NOT NULL DEFAULT 1,
    detected_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_exposures_asset ON exposures(asset_id);
CREATE INDEX IF NOT EXISTS idx_exposures_severity ON exposures(severity);

CREATE TABLE IF NOT EXISTS risks (
    id TEXT PRIMARY KEY,
    asset_id TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    asset_name TEXT NOT NULL DEFAULT '',
    asset_risk_score REAL NOT NULL DEFAULT 0,
    configuration_risk_score REAL NOT NULL DEFAULT 0,
    exposure_risk_score REAL NOT NULL DEFAULT 0,
    overall_score REAL NOT NULL DEFAULT 0,
    risk_level TEXT NOT NULL DEFAULT 'none',
    trend TEXT NOT NULL DEFAULT 'stable',
    trend_delta REAL NOT NULL DEFAULT 0,
    calculated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS recommendations (
    id TEXT PRIMARY KEY,
    finding_id TEXT DEFAULT '',
    asset_id TEXT REFERENCES assets(id) ON DELETE CASCADE,
    asset_name TEXT DEFAULT '',
    title TEXT NOT NULL,
    explanation TEXT NOT NULL DEFAULT '',
    impact TEXT DEFAULT '',
    priority TEXT NOT NULL DEFAULT 'p3_medium',
    steps TEXT DEFAULT '[]',
    references TEXT DEFAULT '',
    estimated_effort TEXT DEFAULT '',
    category TEXT DEFAULT '',
    is_completed INTEGER NOT NULL DEFAULT 0,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS historical_metrics (
    id TEXT PRIMARY KEY,
    metric_date TEXT NOT NULL UNIQUE,
    total_assets INTEGER NOT NULL DEFAULT 0,
    active_assets INTEGER NOT NULL DEFAULT 0,
    total_findings INTEGER NOT NULL DEFAULT 0,
    critical_findings INTEGER NOT NULL DEFAULT 0,
    high_findings INTEGER NOT NULL DEFAULT 0,
    medium_findings INTEGER NOT NULL DEFAULT 0,
    low_findings INTEGER NOT NULL DEFAULT 0,
    new_findings INTEGER NOT NULL DEFAULT 0,
    resolved_findings INTEGER NOT NULL DEFAULT 0,
    total_exposures INTEGER NOT NULL DEFAULT 0,
    risk_score REAL NOT NULL DEFAULT 0,
    security_score REAL NOT NULL DEFAULT 0,
    expiring_certs INTEGER NOT NULL DEFAULT 0,
    scan_count INTEGER NOT NULL DEFAULT 0,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS scan_sessions (
    id TEXT PRIMARY KEY,
    scan_type TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    target TEXT DEFAULT '',
    total_assets INTEGER NOT NULL DEFAULT 0,
    scanned_assets INTEGER NOT NULL DEFAULT 0,
    findings_count INTEGER NOT NULL DEFAULT 0,
    error_message TEXT DEFAULT '',
    progress REAL NOT NULL DEFAULT 0,
    started_at DATETIME,
    completed_at DATETIME,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
`
	_, err := s.db.Exec(schema)
	return err
}



func (s *Store) UpsertAsset(ctx context.Context, a *models.Asset) error {
	if a.ID == "" {
		a.ID = uuid.NewString()
		a.CreatedAt = time.Now()
		a.FirstSeenAt = time.Now()
	}
	a.LastSeenAt = time.Now()

	_, err := s.db.ExecContext(ctx, `
		INSERT INTO assets (id,name,type,value,environment,status,owner,team,tags,
		    risk_score,risk_level,is_monitored,is_critical,first_seen_at,last_seen_at,created_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET
		    name=excluded.name, type=excluded.type, value=excluded.value,
		    environment=excluded.environment, status=excluded.status,
		    owner=excluded.owner, team=excluded.team, tags=excluded.tags,
		    risk_score=excluded.risk_score, risk_level=excluded.risk_level,
		    is_monitored=excluded.is_monitored, is_critical=excluded.is_critical,
		    last_seen_at=excluded.last_seen_at`,
		a.ID, a.Name, a.Type, a.Value, a.Environment, a.Status,
		a.Owner, a.Team, a.Tags, a.RiskScore, a.RiskLevel,
		a.IsMonitored, a.IsCritical, a.FirstSeenAt, a.LastSeenAt, a.CreatedAt,
	)
	return err
}

func (s *Store) ListAssets(ctx context.Context) ([]*models.Asset, error) {
	var assets []*models.Asset
	err := s.db.SelectContext(ctx, &assets, `SELECT * FROM assets ORDER BY risk_score DESC, created_at DESC`)
	return assets, err
}

func (s *Store) GetAsset(ctx context.Context, id string) (*models.Asset, error) {
	var a models.Asset
	err := s.db.GetContext(ctx, &a, `SELECT * FROM assets WHERE id=?`, id)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return &a, err
}

func (s *Store) CountAssets(ctx context.Context) (int, error) {
	var n int
	err := s.db.GetContext(ctx, &n, `SELECT COUNT(*) FROM assets`)
	return n, err
}

func (s *Store) DeleteAsset(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM assets WHERE id=?`, id)
	return err
}



func (s *Store) UpsertFinding(ctx context.Context, f *models.Finding) error {
	if f.ID == "" {
		f.ID = uuid.NewString()
		f.CreatedAt = time.Now()
		f.FirstSeenAt = time.Now()
	}
	f.LastSeenAt = time.Now()

	_, err := s.db.ExecContext(ctx, `
		INSERT INTO findings (id,asset_id,asset_name,title,description,severity,status,
		    category,affected_url,evidence,impact,remediation,references,
		    cvss_score,confidence,hash,first_seen_at,last_seen_at,created_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(hash) DO UPDATE SET
		    last_seen_at=excluded.last_seen_at,
		    severity=excluded.severity,
		    evidence=excluded.evidence`,
		f.ID, f.AssetID, f.AssetName, f.Title, f.Description, f.Severity, f.Status,
		f.Category, f.AffectedURL, f.Evidence, f.Impact, f.Remediation, f.References,
		f.CVSSScore, f.Confidence, f.Hash, f.FirstSeenAt, f.LastSeenAt, f.CreatedAt,
	)
	return err
}

func (s *Store) ListFindings(ctx context.Context, assetID string) ([]*models.Finding, error) {
	var findings []*models.Finding
	q := `SELECT * FROM findings WHERE status != 'resolved'`
	args := []interface{}{}
	if assetID != "" {
		q += ` AND asset_id=?`
		args = append(args, assetID)
	}
	q += ` ORDER BY CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END, created_at DESC`
	err := s.db.SelectContext(ctx, &findings, q, args...)
	return findings, err
}

func (s *Store) CountFindingsBySeverity(ctx context.Context) (map[string]int, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT severity, COUNT(*) FROM findings WHERE status='open' GROUP BY severity`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := map[string]int{}
	for rows.Next() {
		var sev string
		var count int
		if err := rows.Scan(&sev, &count); err == nil {
			result[sev] = count
		}
	}
	return result, nil
}

func (s *Store) ResolveFinding(ctx context.Context, id string) error {
	now := time.Now()
	_, err := s.db.ExecContext(ctx,
		`UPDATE findings SET status='resolved', resolved_at=? WHERE id=?`, now, id)
	return err
}



func (s *Store) UpsertCertificate(ctx context.Context, c *models.Certificate) error {
	if c.ID == "" {
		c.ID = uuid.NewString()
		c.CreatedAt = time.Now()
	}
	c.LastCheckedAt = time.Now()

	c.DaysUntilExpiry = int(time.Until(c.NotAfter).Hours() / 24)
	c.IsExpired = c.NotAfter.Before(time.Now())

	_, err := s.db.ExecContext(ctx, `
		INSERT INTO certificates (id,asset_id,domain,common_name,issuer,key_type,key_bits,
		    signature_algo,tls_version,not_before,not_after,days_until_expiry,is_expired,
		    is_self_signed,is_wildcard,chain_valid,status,fingerprint,serial_number,sans,
		    last_checked_at,created_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET
		    days_until_expiry=excluded.days_until_expiry,
		    is_expired=excluded.is_expired,
		    status=excluded.status,
		    last_checked_at=excluded.last_checked_at`,
		c.ID, c.AssetID, c.Domain, c.CommonName, c.Issuer, c.KeyType, c.KeyBits,
		c.SignatureAlgo, c.TLSVersion, c.NotBefore, c.NotAfter, c.DaysUntilExpiry,
		c.IsExpired, c.IsSelfSigned, c.IsWildcard, c.ChainValid, c.Status,
		c.Fingerprint, c.SerialNumber, c.SANs, c.LastCheckedAt, c.CreatedAt,
	)
	return err
}

func (s *Store) ListCertificates(ctx context.Context) ([]*models.Certificate, error) {
	var certs []*models.Certificate
	err := s.db.SelectContext(ctx, &certs,
		`SELECT * FROM certificates ORDER BY days_until_expiry ASC`)
	return certs, err
}

func (s *Store) CountExpiringCerts(ctx context.Context, days int) (int, error) {
	var n int
	err := s.db.GetContext(ctx, &n,
		`SELECT COUNT(*) FROM certificates WHERE days_until_expiry <= ? AND is_expired=0`, days)
	return n, err
}



func (s *Store) UpsertDNSSecurity(ctx context.Context, r *models.DNSSecurityResult) error {
	if r.ID == "" {
		r.ID = uuid.NewString()
	}
	r.AnalyzedAt = time.Now()
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO dns_security (id,asset_id,domain,spf_status,spf_record,dkim_status,
		    dmarc_status,dmarc_record,dmarc_policy,mta_sts_status,dnssec_status,overall_score,analyzed_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET
		    spf_status=excluded.spf_status, dmarc_status=excluded.dmarc_status,
		    overall_score=excluded.overall_score, analyzed_at=excluded.analyzed_at`,
		r.ID, r.AssetID, r.Domain, r.SPFStatus, r.SPFRecord, r.DKIMStatus,
		r.DMARCStatus, r.DMARCRecord, r.DMARCPolicy, r.MTASTSStatus, r.DNSSECStatus,
		r.OverallScore, r.AnalyzedAt,
	)
	return err
}

func (s *Store) GetDNSSecurity(ctx context.Context, assetID string) (*models.DNSSecurityResult, error) {
	var r models.DNSSecurityResult
	err := s.db.GetContext(ctx, &r,
		`SELECT * FROM dns_security WHERE asset_id=? ORDER BY analyzed_at DESC LIMIT 1`, assetID)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return &r, err
}



func (s *Store) UpsertWebSecurity(ctx context.Context, r *models.WebSecurityResult) error {
	if r.ID == "" {
		r.ID = uuid.NewString()
	}
	r.AnalyzedAt = time.Now()
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO web_security (id,asset_id,url,grade,score,tls_version,has_hsts,has_csp,
		    has_x_frame_options,has_x_content_type_options,has_referrer_policy,has_permissions_policy,
		    cookies_secure,cookies_httponly,http_to_https,server_version_disclosed,server_header,issues,analyzed_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET
		    grade=excluded.grade, score=excluded.score, has_hsts=excluded.has_hsts,
		    has_csp=excluded.has_csp, issues=excluded.issues, analyzed_at=excluded.analyzed_at`,
		r.ID, r.AssetID, r.URL, r.Grade, r.Score, r.TLSVersion, r.HasHSTS, r.HasCSP,
		r.HasXFrameOptions, r.HasXContentTypeOptions, r.HasReferrerPolicy, r.HasPermissionsPolicy,
		r.CookiesSecure, r.CookiesHTTPOnly, r.HTTPToHTTPS, r.ServerVersionDisclosed,
		r.ServerHeader, r.Issues, r.AnalyzedAt,
	)
	return err
}



func (s *Store) UpsertExposure(ctx context.Context, e *models.Exposure) error {
	if e.ID == "" {
		e.ID = uuid.NewString()
		e.CreatedAt = time.Now()
		e.DetectedAt = time.Now()
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO exposures (id,asset_id,asset_name,exposure_type,title,description,url,
		    severity,confidence,business_impact,is_active,detected_at,created_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET
		    is_active=excluded.is_active, severity=excluded.severity, detected_at=excluded.detected_at`,
		e.ID, e.AssetID, e.AssetName, e.ExposureType, e.Title, e.Description, e.URL,
		e.Severity, e.Confidence, e.BusinessImpact, e.IsActive, e.DetectedAt, e.CreatedAt,
	)
	return err
}

func (s *Store) ListExposures(ctx context.Context) ([]*models.Exposure, error) {
	var exposures []*models.Exposure
	err := s.db.SelectContext(ctx, &exposures,
		`SELECT * FROM exposures WHERE is_active=1 ORDER BY severity DESC, detected_at DESC`)
	return exposures, err
}



func (s *Store) UpsertRisk(ctx context.Context, r *models.RiskScore) error {
	if r.ID == "" {
		r.ID = uuid.NewString()
	}
	r.CalculatedAt = time.Now()
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO risks (id,asset_id,asset_name,asset_risk_score,configuration_risk_score,
		    exposure_risk_score,overall_score,risk_level,trend,trend_delta,calculated_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET
		    overall_score=excluded.overall_score, risk_level=excluded.risk_level,
		    trend=excluded.trend, trend_delta=excluded.trend_delta, calculated_at=excluded.calculated_at`,
		r.ID, r.AssetID, r.AssetName, r.AssetRiskScore, r.ConfigurationRiskScore,
		r.ExposureRiskScore, r.OverallScore, r.RiskLevel, r.Trend, r.TrendDelta, r.CalculatedAt,
	)
	return err
}

func (s *Store) ListRisks(ctx context.Context) ([]*models.RiskScore, error) {
	var risks []*models.RiskScore
	err := s.db.SelectContext(ctx, &risks,
		`SELECT * FROM risks ORDER BY overall_score DESC`)
	return risks, err
}



func (s *Store) UpsertRecommendation(ctx context.Context, r *models.Recommendation) error {
	if r.ID == "" {
		r.ID = uuid.NewString()
		r.CreatedAt = time.Now()
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO recommendations (id,finding_id,asset_id,asset_name,title,explanation,
		    impact,priority,steps,references,estimated_effort,category,is_completed,created_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET
		    priority=excluded.priority, is_completed=excluded.is_completed`,
		r.ID, r.FindingID, r.AssetID, r.AssetName, r.Title, r.Explanation,
		r.Impact, r.Priority, r.Steps, r.References, r.EstimatedEffort,
		r.Category, r.IsCompleted, r.CreatedAt,
	)
	return err
}

func (s *Store) ListRecommendations(ctx context.Context) ([]*models.Recommendation, error) {
	var recs []*models.Recommendation
	err := s.db.SelectContext(ctx, &recs,
		`SELECT * FROM recommendations WHERE is_completed=0 ORDER BY CASE priority WHEN 'p1_critical' THEN 1 WHEN 'p2_high' THEN 2 WHEN 'p3_medium' THEN 3 WHEN 'p4_low' THEN 4 ELSE 5 END, created_at DESC`)
	return recs, err
}



func (s *Store) UpsertHistoricalMetric(ctx context.Context, m *models.HistoricalMetric) error {
	if m.ID == "" {
		m.ID = uuid.NewString()
		m.CreatedAt = time.Now()
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO historical_metrics (id,metric_date,total_assets,active_assets,total_findings,
		    critical_findings,high_findings,medium_findings,low_findings,new_findings,
		    resolved_findings,total_exposures,risk_score,security_score,expiring_certs,scan_count,created_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(metric_date) DO UPDATE SET
		    total_assets=excluded.total_assets, total_findings=excluded.total_findings,
		    risk_score=excluded.risk_score, security_score=excluded.security_score,
		    scan_count=scan_count+1`,
		m.ID, m.MetricDate, m.TotalAssets, m.ActiveAssets, m.TotalFindings,
		m.CriticalFindings, m.HighFindings, m.MediumFindings, m.LowFindings,
		m.NewFindings, m.ResolvedFindings, m.TotalExposures, m.RiskScore,
		m.SecurityScore, m.ExpiringCerts, m.ScanCount, m.CreatedAt,
	)
	return err
}

func (s *Store) ListHistoricalMetrics(ctx context.Context, days int) ([]*models.HistoricalMetric, error) {
	var metrics []*models.HistoricalMetric
	err := s.db.SelectContext(ctx, &metrics,
		`SELECT * FROM historical_metrics ORDER BY metric_date DESC LIMIT ?`, days)
	return metrics, err
}



func (s *Store) CreateScanSession(ctx context.Context, sess *models.ScanSession) error {
	sess.ID = uuid.NewString()
	sess.CreatedAt = time.Now()
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO scan_sessions (id,scan_type,status,target,total_assets,scanned_assets,
		    findings_count,error_message,progress,started_at,completed_at,created_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
		sess.ID, sess.ScanType, sess.Status, sess.Target, sess.TotalAssets,
		sess.ScannedAssets, sess.FindingsCount, sess.ErrorMessage, sess.Progress,
		sess.StartedAt, sess.CompletedAt, sess.CreatedAt,
	)
	return err
}

func (s *Store) UpdateScanSession(ctx context.Context, sess *models.ScanSession) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE scan_sessions SET status=?,scanned_assets=?,findings_count=?,
		    error_message=?,progress=?,started_at=?,completed_at=? WHERE id=?`,
		sess.Status, sess.ScannedAssets, sess.FindingsCount, sess.ErrorMessage,
		sess.Progress, sess.StartedAt, sess.CompletedAt, sess.ID,
	)
	return err
}

func (s *Store) ListScanSessions(ctx context.Context, limit int) ([]*models.ScanSession, error) {
	var sessions []*models.ScanSession
	err := s.db.SelectContext(ctx, &sessions,
		`SELECT * FROM scan_sessions ORDER BY created_at DESC LIMIT ?`, limit)
	return sessions, err
}



type DashboardStats struct {
	TotalAssets      int     `db:"total_assets"`
	ActiveAssets     int     `db:"active_assets"`
	TotalFindings    int     `db:"total_findings"`
	CriticalFindings int     `db:"critical_findings"`
	HighFindings     int     `db:"high_findings"`
	MediumFindings   int     `db:"medium_findings"`
	LowFindings      int     `db:"low_findings"`
	TotalExposures   int     `db:"total_exposures"`
	ExpiringCerts    int     `db:"expiring_certs"`
	OrgRiskScore     float64 `db:"org_risk_score"`
}

func (s *Store) GetDashboardStats(ctx context.Context) (*DashboardStats, error) {
	stats := &DashboardStats{}


	_ = s.db.GetContext(ctx, &stats.TotalAssets, `SELECT COUNT(*) FROM assets`)
	_ = s.db.GetContext(ctx, &stats.ActiveAssets, `SELECT COUNT(*) FROM assets WHERE status='active'`)


	_ = s.db.GetContext(ctx, &stats.TotalFindings, `SELECT COUNT(*) FROM findings WHERE status='open'`)
	_ = s.db.GetContext(ctx, &stats.CriticalFindings, `SELECT COUNT(*) FROM findings WHERE severity='critical' AND status='open'`)
	_ = s.db.GetContext(ctx, &stats.HighFindings, `SELECT COUNT(*) FROM findings WHERE severity='high' AND status='open'`)
	_ = s.db.GetContext(ctx, &stats.MediumFindings, `SELECT COUNT(*) FROM findings WHERE severity='medium' AND status='open'`)
	_ = s.db.GetContext(ctx, &stats.LowFindings, `SELECT COUNT(*) FROM findings WHERE severity='low' AND status='open'`)


	_ = s.db.GetContext(ctx, &stats.TotalExposures, `SELECT COUNT(*) FROM exposures WHERE is_active=1`)


	_ = s.db.GetContext(ctx, &stats.ExpiringCerts, `SELECT COUNT(*) FROM certificates WHERE days_until_expiry <= 30 AND is_expired=0`)


	_ = s.db.GetContext(ctx, &stats.OrgRiskScore, `SELECT COALESCE(AVG(risk_score),0) FROM assets`)

	return stats, nil
}
