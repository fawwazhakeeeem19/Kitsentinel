package models

import "time"



type AssetType string
type AssetStatus string
type Environment string
type RiskLevel string

const (
	AssetDomain    AssetType = "domain"
	AssetSubdomain AssetType = "subdomain"
	AssetWebApp    AssetType = "web_app"
	AssetAPI       AssetType = "api"
	AssetServer    AssetType = "server"
	AssetStorage   AssetType = "storage"
	AssetMail      AssetType = "mail"
	AssetCDN       AssetType = "cdn"
	AssetUnknown   AssetType = "unknown"
)

const (
	EnvProduction  Environment = "production"
	EnvStaging     Environment = "staging"
	EnvDevelopment Environment = "development"
	EnvLegacy      Environment = "legacy"
	EnvUnknown     Environment = "unknown"
)

const (
	RiskNone     RiskLevel = "none"
	RiskLow      RiskLevel = "low"
	RiskMedium   RiskLevel = "medium"
	RiskHigh     RiskLevel = "high"
	RiskCritical RiskLevel = "critical"
)

type Asset struct {
	ID           string      `db:"id" json:"id"`
	Name         string      `db:"name" json:"name"`
	Type         AssetType   `db:"type" json:"type"`
	Value        string      `db:"value" json:"value"`
	Environment  Environment `db:"environment" json:"environment"`
	Status       AssetStatus `db:"status" json:"status"`
	Owner        string      `db:"owner" json:"owner"`
	Team         string      `db:"team" json:"team"`
	Tags         string      `db:"tags" json:"tags"` // comma-separated
	RiskScore    float64     `db:"risk_score" json:"risk_score"`
	RiskLevel    RiskLevel   `db:"risk_level" json:"risk_level"`
	IsMonitored  bool        `db:"is_monitored" json:"is_monitored"`
	IsCritical   bool        `db:"is_critical" json:"is_critical"`
	FirstSeenAt  time.Time   `db:"first_seen_at" json:"first_seen_at"`
	LastSeenAt   time.Time   `db:"last_seen_at" json:"last_seen_at"`
	CreatedAt    time.Time   `db:"created_at" json:"created_at"`
}



type Severity string
type FindingStatus string
type Category string

const (
	SevCritical Severity = "critical"
	SevHigh     Severity = "high"
	SevMedium   Severity = "medium"
	SevLow      Severity = "low"
	SevInfo     Severity = "info"
)

const (
	StatusOpen          FindingStatus = "open"
	StatusResolved      FindingStatus = "resolved"
	StatusAccepted      FindingStatus = "accepted"
	StatusFalsePositive FindingStatus = "false_positive"
)

const (
	CatTLS         Category = "tls"
	CatHeaders     Category = "headers"
	CatCookies     Category = "cookies"
	CatCSP         Category = "csp"
	CatDNS         Category = "dns"
	CatEmail       Category = "email_security"
	CatExposure    Category = "exposure"
	CatInfoDisc    Category = "info_disclosure"
	CatConfig      Category = "configuration"
	CatCertificate Category = "certificate"
)

type Finding struct {
	ID           string        `db:"id" json:"id"`
	AssetID      string        `db:"asset_id" json:"asset_id"`
	AssetName    string        `db:"asset_name" json:"asset_name"`
	Title        string        `db:"title" json:"title"`
	Description  string        `db:"description" json:"description"`
	Severity     Severity      `db:"severity" json:"severity"`
	Status       FindingStatus `db:"status" json:"status"`
	Category     Category      `db:"category" json:"category"`
	AffectedURL  string        `db:"affected_url" json:"affected_url"`
	Evidence     string        `db:"evidence" json:"evidence"`
	Impact       string        `db:"impact" json:"impact"`
	Remediation  string        `db:"remediation" json:"remediation"`
	References   string        `db:"references" json:"references"`
	CVSSScore    float64       `db:"cvss_score" json:"cvss_score"`
	Confidence   float64       `db:"confidence" json:"confidence"`
	Hash         string        `db:"hash" json:"hash"`
	FirstSeenAt  time.Time     `db:"first_seen_at" json:"first_seen_at"`
	LastSeenAt   time.Time     `db:"last_seen_at" json:"last_seen_at"`
	ResolvedAt   *time.Time    `db:"resolved_at" json:"resolved_at,omitempty"`
	CreatedAt    time.Time     `db:"created_at" json:"created_at"`
}



type CertStatus string

const (
	CertValid        CertStatus = "valid"
	CertExpired      CertStatus = "expired"
	CertExpiringSoon CertStatus = "expiring_soon"
	CertSelfSigned   CertStatus = "self_signed"
	CertWeakKey      CertStatus = "weak_key"
	CertInvalidChain CertStatus = "invalid_chain"
)

type Certificate struct {
	ID              string     `db:"id" json:"id"`
	AssetID         string     `db:"asset_id" json:"asset_id"`
	Domain          string     `db:"domain" json:"domain"`
	CommonName      string     `db:"common_name" json:"common_name"`
	Issuer          string     `db:"issuer" json:"issuer"`
	KeyType         string     `db:"key_type" json:"key_type"`
	KeyBits         int        `db:"key_bits" json:"key_bits"`
	SignatureAlgo   string     `db:"signature_algo" json:"signature_algo"`
	TLSVersion      string     `db:"tls_version" json:"tls_version"`
	NotBefore       time.Time  `db:"not_before" json:"not_before"`
	NotAfter        time.Time  `db:"not_after" json:"not_after"`
	DaysUntilExpiry int        `db:"days_until_expiry" json:"days_until_expiry"`
	IsExpired       bool       `db:"is_expired" json:"is_expired"`
	IsSelfSigned    bool       `db:"is_self_signed" json:"is_self_signed"`
	IsWildcard      bool       `db:"is_wildcard" json:"is_wildcard"`
	ChainValid      bool       `db:"chain_valid" json:"chain_valid"`
	Status          CertStatus `db:"status" json:"status"`
	Fingerprint     string     `db:"fingerprint" json:"fingerprint"`
	SerialNumber    string     `db:"serial_number" json:"serial_number"`
	SANs            string     `db:"sans" json:"sans"` // comma-separated
	LastCheckedAt   time.Time  `db:"last_checked_at" json:"last_checked_at"`
	CreatedAt       time.Time  `db:"created_at" json:"created_at"`
}



type CheckStatus string

const (
	CheckPass    CheckStatus = "pass"
	CheckFail    CheckStatus = "fail"
	CheckWarning CheckStatus = "warning"
	CheckNA      CheckStatus = "not_configured"
)

type DNSSecurityResult struct {
	ID           string      `db:"id" json:"id"`
	AssetID      string      `db:"asset_id" json:"asset_id"`
	Domain       string      `db:"domain" json:"domain"`
	SPFStatus    CheckStatus `db:"spf_status" json:"spf_status"`
	SPFRecord    string      `db:"spf_record" json:"spf_record"`
	DKIMStatus   CheckStatus `db:"dkim_status" json:"dkim_status"`
	DMARCStatus  CheckStatus `db:"dmarc_status" json:"dmarc_status"`
	DMARCRecord  string      `db:"dmarc_record" json:"dmarc_record"`
	DMARCPolicy  string      `db:"dmarc_policy" json:"dmarc_policy"`
	MTASTSStatus CheckStatus `db:"mta_sts_status" json:"mta_sts_status"`
	DNSSECStatus CheckStatus `db:"dnssec_status" json:"dnssec_status"`
	OverallScore float64     `db:"overall_score" json:"overall_score"`
	AnalyzedAt   time.Time   `db:"analyzed_at" json:"analyzed_at"`
}



type WebSecurityResult struct {
	ID                       string    `db:"id" json:"id"`
	AssetID                  string    `db:"asset_id" json:"asset_id"`
	URL                      string    `db:"url" json:"url"`
	Grade                    string    `db:"grade" json:"grade"`
	Score                    float64   `db:"score" json:"score"`
	TLSVersion               string    `db:"tls_version" json:"tls_version"`
	HasHSTS                  bool      `db:"has_hsts" json:"has_hsts"`
	HasCSP                   bool      `db:"has_csp" json:"has_csp"`
	HasXFrameOptions         bool      `db:"has_x_frame_options" json:"has_x_frame_options"`
	HasXContentTypeOptions   bool      `db:"has_x_content_type_options" json:"has_x_content_type_options"`
	HasReferrerPolicy        bool      `db:"has_referrer_policy" json:"has_referrer_policy"`
	HasPermissionsPolicy     bool      `db:"has_permissions_policy" json:"has_permissions_policy"`
	CookiesSecure            bool      `db:"cookies_secure" json:"cookies_secure"`
	CookiesHTTPOnly          bool      `db:"cookies_httponly" json:"cookies_httponly"`
	HTTPToHTTPS              bool      `db:"http_to_https" json:"http_to_https"`
	ServerVersionDisclosed   bool      `db:"server_version_disclosed" json:"server_version_disclosed"`
	ServerHeader             string    `db:"server_header" json:"server_header"`
	Issues                   string    `db:"issues" json:"issues"` // JSON array
	AnalyzedAt               time.Time `db:"analyzed_at" json:"analyzed_at"`
}



type ExposureType string

const (
	ExposureAdminPanel     ExposureType = "admin_panel"
	ExposureDirectoryList  ExposureType = "directory_listing"
	ExposurePublicStorage  ExposureType = "public_storage"
	ExposureConfigFile     ExposureType = "config_file"
	ExposureDebugPage      ExposureType = "debug_page"
	ExposureBackupFile     ExposureType = "backup_file"
	ExposureInfoDisclosure ExposureType = "info_disclosure"
	ExposureTestEnv        ExposureType = "test_environment"
)

type Exposure struct {
	ID             string       `db:"id" json:"id"`
	AssetID        string       `db:"asset_id" json:"asset_id"`
	AssetName      string       `db:"asset_name" json:"asset_name"`
	ExposureType   ExposureType `db:"exposure_type" json:"exposure_type"`
	Title          string       `db:"title" json:"title"`
	Description    string       `db:"description" json:"description"`
	URL            string       `db:"url" json:"url"`
	Severity       Severity     `db:"severity" json:"severity"`
	Confidence     float64      `db:"confidence" json:"confidence"`
	BusinessImpact string       `db:"business_impact" json:"business_impact"`
	IsActive       bool         `db:"is_active" json:"is_active"`
	DetectedAt     time.Time    `db:"detected_at" json:"detected_at"`
	CreatedAt      time.Time    `db:"created_at" json:"created_at"`
}



type RiskScore struct {
	ID                      string    `db:"id" json:"id"`
	AssetID                 string    `db:"asset_id" json:"asset_id"`
	AssetName               string    `db:"asset_name" json:"asset_name"`
	AssetRiskScore          float64   `db:"asset_risk_score" json:"asset_risk_score"`
	ConfigurationRiskScore  float64   `db:"configuration_risk_score" json:"configuration_risk_score"`
	ExposureRiskScore       float64   `db:"exposure_risk_score" json:"exposure_risk_score"`
	OverallScore            float64   `db:"overall_score" json:"overall_score"`
	RiskLevel               RiskLevel `db:"risk_level" json:"risk_level"`
	Trend                   string    `db:"trend" json:"trend"` // improving, degrading, stable
	TrendDelta              float64   `db:"trend_delta" json:"trend_delta"`
	CalculatedAt            time.Time `db:"calculated_at" json:"calculated_at"`
}

type OrgRiskSummary struct {
	OverallScore      float64            `json:"overall_score"`
	RiskLevel         RiskLevel          `json:"risk_level"`
	TotalAssets       int                `json:"total_assets"`
	CriticalAssets    int                `json:"critical_assets"`
	TotalFindings     int                `json:"total_findings"`
	CriticalFindings  int                `json:"critical_findings"`
	HighFindings      int                `json:"high_findings"`
	MediumFindings    int                `json:"medium_findings"`
	LowFindings       int                `json:"low_findings"`
	TotalExposures    int                `json:"total_exposures"`
	ExpiringCerts     int                `json:"expiring_certs"`
	ByCategory        map[string]int     `json:"by_category"`
	TopRisks          []*RiskScore       `json:"top_risks"`
}



type Priority string

const (
	PriorityP1Critical     Priority = "p1_critical"
	PriorityP2High         Priority = "p2_high"
	PriorityP3Medium       Priority = "p3_medium"
	PriorityP4Low          Priority = "p4_low"
	PriorityP5Informational Priority = "p5_info"
)

type Recommendation struct {
	ID               string   `db:"id" json:"id"`
	FindingID        string   `db:"finding_id" json:"finding_id"`
	AssetID          string   `db:"asset_id" json:"asset_id"`
	AssetName        string   `db:"asset_name" json:"asset_name"`
	Title            string   `db:"title" json:"title"`
	Explanation      string   `db:"explanation" json:"explanation"`
	Impact           string   `db:"impact" json:"impact"`
	Priority         Priority `db:"priority" json:"priority"`
	Steps            string   `db:"steps" json:"steps"` // JSON array of strings
	References       string   `db:"references" json:"references"`
	EstimatedEffort  string   `db:"estimated_effort" json:"estimated_effort"`
	Category         string   `db:"category" json:"category"`
	IsCompleted      bool     `db:"is_completed" json:"is_completed"`
	CreatedAt        time.Time `db:"created_at" json:"created_at"`
}



type HistoricalMetric struct {
	ID                 string    `db:"id" json:"id"`
	MetricDate         string    `db:"metric_date" json:"metric_date"` // YYYY-MM-DD
	TotalAssets        int       `db:"total_assets" json:"total_assets"`
	ActiveAssets       int       `db:"active_assets" json:"active_assets"`
	TotalFindings      int       `db:"total_findings" json:"total_findings"`
	CriticalFindings   int       `db:"critical_findings" json:"critical_findings"`
	HighFindings       int       `db:"high_findings" json:"high_findings"`
	MediumFindings     int       `db:"medium_findings" json:"medium_findings"`
	LowFindings        int       `db:"low_findings" json:"low_findings"`
	NewFindings        int       `db:"new_findings" json:"new_findings"`
	ResolvedFindings   int       `db:"resolved_findings" json:"resolved_findings"`
	TotalExposures     int       `db:"total_exposures" json:"total_exposures"`
	RiskScore          float64   `db:"risk_score" json:"risk_score"`
	SecurityScore      float64   `db:"security_score" json:"security_score"`
	ExpiringCerts      int       `db:"expiring_certs" json:"expiring_certs"`
	ScanCount          int       `db:"scan_count" json:"scan_count"`
	CreatedAt          time.Time `db:"created_at" json:"created_at"`
}



type ScanType string
type ScanStatus string

const (
	ScanFull        ScanType = "full"
	ScanInventory   ScanType = "inventory"
	ScanAssessment  ScanType = "assessment"
	ScanExposure    ScanType = "exposure"
	ScanCertificate ScanType = "certificate"
	ScanDNS         ScanType = "dns"
	ScanRisk        ScanType = "risk"
)

const (
	ScanPending   ScanStatus = "pending"
	ScanRunning   ScanStatus = "running"
	ScanDone      ScanStatus = "completed"
	ScanFailed    ScanStatus = "failed"
	ScanCancelled ScanStatus = "cancelled"
)

type ScanSession struct {
	ID             string     `db:"id" json:"id"`
	ScanType       ScanType   `db:"scan_type" json:"scan_type"`
	Status         ScanStatus `db:"status" json:"status"`
	Target         string     `db:"target" json:"target"`
	TotalAssets    int        `db:"total_assets" json:"total_assets"`
	ScannedAssets  int        `db:"scanned_assets" json:"scanned_assets"`
	FindingsCount  int        `db:"findings_count" json:"findings_count"`
	ErrorMessage   string     `db:"error_message" json:"error_message"`
	Progress       float64    `db:"progress" json:"progress"`
	StartedAt      *time.Time `db:"started_at" json:"started_at"`
	CompletedAt    *time.Time `db:"completed_at" json:"completed_at"`
	CreatedAt      time.Time  `db:"created_at" json:"created_at"`
}



type AppConfig struct {
	Target         string   `yaml:"target"`
	Targets        []string `yaml:"targets"`
	DatabasePath   string   `yaml:"database_path"`
	OutputDir      string   `yaml:"output_dir"`
	LogLevel       string   `yaml:"log_level"`
	WorkerCount    int      `yaml:"worker_count"`
	Timeout        int      `yaml:"timeout_seconds"`
	MaxRetries     int      `yaml:"max_retries"`
	UserAgent      string   `yaml:"user_agent"`
	PythonBin      string   `yaml:"python_bin"`
	EnableColor    bool     `yaml:"enable_color"`
	NotifyEmail    string   `yaml:"notify_email"`
	SlackWebhook   string   `yaml:"slack_webhook"`
}
