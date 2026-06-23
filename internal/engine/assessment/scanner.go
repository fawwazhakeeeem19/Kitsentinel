package assessment

import (
	"context"
	"crypto/md5"
	"crypto/rsa"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/kitsentinel/cli/internal/models"
	"github.com/miekg/dns"
)

// ScanResult holds all collected security data for one asset.
type ScanResult struct {
	Asset      *models.Asset
	WebSec     *models.WebSecurityResult
	Cert       *models.Certificate
	DNSSec     *models.DNSSecurityResult
	Findings   []*models.Finding
	Exposures  []*models.Exposure
}

// Scanner performs security posture assessment on a target URL.
type Scanner struct {
	timeout    time.Duration
	userAgent  string
	httpClient *http.Client
}

func NewScanner(timeout time.Duration, userAgent string) *Scanner {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: false},
		DialContext: (&net.Dialer{
			Timeout:   timeout,
			KeepAlive: 15 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout,
	}
	return &Scanner{
		timeout:   timeout,
		userAgent: userAgent,
		httpClient: &http.Client{
			Transport: transport,
			Timeout:   timeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 10 {
					return fmt.Errorf("too many redirects")
				}
				return nil
			},
		},
	}
}

// Assess runs the full security assessment on an asset.
func (s *Scanner) Assess(ctx context.Context, asset *models.Asset) (*ScanResult, error) {
	result := &ScanResult{Asset: asset}

	target := asset.Value
	if !strings.HasPrefix(target, "http") {
		target = "https://" + target
	}

	// 1. HTTP Security Headers + TLS
	webResult, findings, err := s.scanWebSecurity(ctx, target, asset)
	if err == nil {
		result.WebSec = webResult
		result.Findings = append(result.Findings, findings...)
	}

	// 2. TLS Certificate
	cert, certFindings, err := s.scanCertificate(ctx, asset)
	if err == nil {
		result.Cert = cert
		result.Findings = append(result.Findings, certFindings...)
	}

	// 3. DNS Security (SPF, DKIM, DMARC)
	domain := extractDomain(asset.Value)
	dnsSec, dnsFindings, err := s.scanDNSSecurity(ctx, domain, asset)
	if err == nil {
		result.DNSSec = dnsSec
		result.Findings = append(result.Findings, dnsFindings...)
	}

	// 4. Exposure detection
	exposures, expFindings := s.scanExposures(ctx, target, asset)
	result.Exposures = exposures
	result.Findings = append(result.Findings, expFindings...)

	return result, nil
}

// ─── Web Security Scanner ──────────────────────────────────────────────────

func (s *Scanner) scanWebSecurity(ctx context.Context, target string, asset *models.Asset) (*models.WebSecurityResult, []*models.Finding, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("User-Agent", s.userAgent)

	start := time.Now()
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	h := resp.Header
	result := &models.WebSecurityResult{
		AssetID:    asset.ID,
		URL:        target,
		AnalyzedAt: time.Now(),
	}

	var findings []*models.Finding
	var issues []string

	// TLS check
	if resp.TLS != nil {
		switch resp.TLS.Version {
		case tls.VersionTLS13:
			result.TLSVersion = "TLS 1.3"
		case tls.VersionTLS12:
			result.TLSVersion = "TLS 1.2"
		case tls.VersionTLS11:
			result.TLSVersion = "TLS 1.1"
			findings = append(findings, makeFinding(asset, "Weak TLS Version (1.1)",
				"TLS 1.1 is deprecated and should be disabled.",
				models.SevHigh, models.CatTLS, target,
				"Disable TLS 1.1 in your web server configuration. Support only TLS 1.2 and TLS 1.3.",
			))
		case tls.VersionTLS10:
			result.TLSVersion = "TLS 1.0"
			findings = append(findings, makeFinding(asset, "Weak TLS Version (1.0)",
				"TLS 1.0 is deprecated and vulnerable (POODLE, BEAST). Must be disabled.",
				models.SevCritical, models.CatTLS, target,
				"Disable TLS 1.0 and TLS 1.1 immediately. Configure minimum TLS 1.2.",
			))
		}
	}

	_ = start

	// HSTS
	hsts := h.Get("Strict-Transport-Security")
	result.HasHSTS = hsts != ""
	if !result.HasHSTS {
		issues = append(issues, "missing_hsts")
		findings = append(findings, makeFinding(asset,
			"Missing Strict-Transport-Security (HSTS) Header",
			"HSTS header is not set. Without HSTS, browsers may connect over HTTP, enabling downgrade attacks.",
			models.SevHigh, models.CatHeaders, target,
			`Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`,
		))
	}

	// CSP
	csp := h.Get("Content-Security-Policy")
	result.HasCSP = csp != ""
	if !result.HasCSP {
		issues = append(issues, "missing_csp")
		findings = append(findings, makeFinding(asset,
			"Missing Content-Security-Policy (CSP) Header",
			"No CSP header detected. This increases risk of XSS and data injection attacks.",
			models.SevHigh, models.CatCSP, target,
			`Define a Content-Security-Policy. Start with: Content-Security-Policy: default-src 'self'`,
		))
	}

	// X-Frame-Options
	xfo := h.Get("X-Frame-Options")
	result.HasXFrameOptions = xfo != ""
	if !result.HasXFrameOptions {
		issues = append(issues, "missing_x_frame_options")
		findings = append(findings, makeFinding(asset,
			"Missing X-Frame-Options Header",
			"Without X-Frame-Options, the application may be vulnerable to clickjacking attacks.",
			models.SevMedium, models.CatHeaders, target,
			`Add header: X-Frame-Options: DENY  (or SAMEORIGIN if embedding is needed)`,
		))
	}

	// X-Content-Type-Options
	xcto := h.Get("X-Content-Type-Options")
	result.HasXContentTypeOptions = xcto == "nosniff"
	if !result.HasXContentTypeOptions {
		issues = append(issues, "missing_x_content_type_options")
		findings = append(findings, makeFinding(asset,
			"Missing X-Content-Type-Options Header",
			"Without nosniff, browsers may MIME-sniff responses leading to XSS attacks.",
			models.SevMedium, models.CatHeaders, target,
			`Add header: X-Content-Type-Options: nosniff`,
		))
	}

	// Referrer-Policy
	rp := h.Get("Referrer-Policy")
	result.HasReferrerPolicy = rp != ""
	if !result.HasReferrerPolicy {
		issues = append(issues, "missing_referrer_policy")
	}

	// Permissions-Policy
	pp := h.Get("Permissions-Policy")
	result.HasPermissionsPolicy = pp != ""

	// Server header (version disclosure)
	server := h.Get("Server")
	result.ServerHeader = server
	if server != "" && containsVersionInfo(server) {
		result.ServerVersionDisclosed = true
		issues = append(issues, "server_version_disclosed")
		findings = append(findings, makeFinding(asset,
			"Server Version Disclosure",
			fmt.Sprintf("Server header '%s' reveals software version enabling targeted attacks.", server),
			models.SevLow, models.CatInfoDisc, target,
			`Configure web server to suppress version information in the Server header.`,
		))
	}

	// HTTP → HTTPS redirect
	httpURL := strings.Replace(target, "https://", "http://", 1)
	httpReq, _ := http.NewRequestWithContext(ctx, "GET", httpURL, nil)
	httpReq.Header.Set("User-Agent", s.userAgent)
	noRedirectClient := &http.Client{
		Timeout: s.timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	if httpResp, err := noRedirectClient.Do(httpReq); err == nil {
		defer httpResp.Body.Close()
		loc := httpResp.Header.Get("Location")
		result.HTTPToHTTPS = strings.HasPrefix(loc, "https://")
		if !result.HTTPToHTTPS {
			issues = append(issues, "no_http_redirect")
			findings = append(findings, makeFinding(asset,
				"HTTP Not Redirected to HTTPS",
				"The site does not redirect HTTP traffic to HTTPS, leaving data unencrypted in transit.",
				models.SevHigh, models.CatTLS, target,
				`Configure 301 permanent redirect from HTTP to HTTPS on your web server.`,
			))
		}
	}

	// Calculate score and grade
	result.Score, result.Grade = calculateWebGrade(result, issues)
	result.Issues = "[" + strings.Join(quoteAll(issues), ",") + "]"

	return result, findings, nil
}

// ─── Certificate Scanner ───────────────────────────────────────────────────

func (s *Scanner) scanCertificate(ctx context.Context, asset *models.Asset) (*models.Certificate, []*models.Finding, error) {
	host := extractDomain(asset.Value)
	addr := net.JoinHostPort(host, "443")

	dialer := &net.Dialer{Timeout: s.timeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: false,
	})
	if err != nil {
		// Try with InsecureSkipVerify to still get cert info
		conn, err = tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
			ServerName:         host,
			InsecureSkipVerify: true,
		})
		if err != nil {
			return nil, nil, err
		}
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil, nil, fmt.Errorf("no certificates found")
	}

	leaf := certs[0]
	tlsVer := tlsVersionString(conn.ConnectionState().Version)

	cert := &models.Certificate{
		AssetID:      asset.ID,
		Domain:       host,
		CommonName:   leaf.Subject.CommonName,
		Issuer:       leaf.Issuer.CommonName,
		NotBefore:    leaf.NotBefore,
		NotAfter:     leaf.NotAfter,
		TLSVersion:   tlsVer,
		SerialNumber: leaf.SerialNumber.String(),
		IsWildcard:   strings.HasPrefix(leaf.Subject.CommonName, "*."),
		IsSelfSigned: leaf.Issuer.CommonName == leaf.Subject.CommonName,
		ChainValid:   len(certs) > 1,
		Fingerprint:  fmt.Sprintf("%x", md5.Sum(leaf.Raw)),
	}

	// Key info
	switch leaf.PublicKeyAlgorithm.String() {
	case "RSA":
		cert.KeyType = "RSA"
		if rsaKey, ok := leaf.PublicKey.(*rsa.PublicKey); ok {
			cert.KeyBits = rsaKey.N.BitLen()
		}
	case "ECDSA":
		cert.KeyType = "ECDSA"
		cert.KeyBits = 256
	}

	cert.SignatureAlgo = leaf.SignatureAlgorithm.String()

	// SANs
	sans := leaf.DNSNames
	cert.SANs = strings.Join(sans, ",")

	// Status
	now := time.Now()
	cert.DaysUntilExpiry = int(leaf.NotAfter.Sub(now).Hours() / 24)
	cert.IsExpired = leaf.NotAfter.Before(now)

	switch {
	case cert.IsExpired:
		cert.Status = models.CertExpired
	case cert.DaysUntilExpiry <= 14:
		cert.Status = models.CertExpiringSoon
	case cert.IsSelfSigned:
		cert.Status = models.CertSelfSigned
	case cert.KeyType == "RSA" && cert.KeyBits < 2048:
		cert.Status = models.CertWeakKey
	default:
		cert.Status = models.CertValid
	}

	// Generate findings from cert issues
	var findings []*models.Finding

	if cert.IsExpired {
		findings = append(findings, makeFinding(asset,
			fmt.Sprintf("SSL Certificate Expired — %s", host),
			fmt.Sprintf("The SSL certificate for %s expired on %s. All visitors receive SSL errors.", host, leaf.NotAfter.Format("2006-01-02")),
			models.SevCritical, models.CatCertificate, "https://"+host,
			"Renew the SSL certificate immediately. Use certbot for Let's Encrypt automation.",
		))
	} else if cert.DaysUntilExpiry <= 14 {
		findings = append(findings, makeFinding(asset,
			fmt.Sprintf("SSL Certificate Expiring in %d Days — %s", cert.DaysUntilExpiry, host),
			fmt.Sprintf("Certificate for %s expires on %s. Expiry causes service outages.", host, leaf.NotAfter.Format("2006-01-02")),
			models.SevHigh, models.CatCertificate, "https://"+host,
			"Renew the certificate now. Verify auto-renewal is configured (certbot cron, ACME).",
		))
	} else if cert.DaysUntilExpiry <= 30 {
		findings = append(findings, makeFinding(asset,
			fmt.Sprintf("SSL Certificate Expiring Soon — %d Days — %s", cert.DaysUntilExpiry, host),
			fmt.Sprintf("Certificate expires in %d days on %s.", cert.DaysUntilExpiry, leaf.NotAfter.Format("2006-01-02")),
			models.SevMedium, models.CatCertificate, "https://"+host,
			"Schedule certificate renewal. Verify auto-renewal scripts.",
		))
	}

	if cert.IsSelfSigned {
		findings = append(findings, makeFinding(asset,
			"Self-Signed SSL Certificate",
			"Self-signed certificates are not trusted by browsers and generate security warnings for users.",
			models.SevHigh, models.CatCertificate, "https://"+host,
			"Replace with a certificate from a trusted CA. Use Let's Encrypt for free trusted certs.",
		))
	}

	if cert.KeyType == "RSA" && cert.KeyBits < 2048 {
		findings = append(findings, makeFinding(asset,
			fmt.Sprintf("Weak RSA Key Size — %d bits", cert.KeyBits),
			"RSA keys below 2048 bits are considered cryptographically weak.",
			models.SevHigh, models.CatCertificate, "https://"+host,
			"Generate a new certificate with RSA-4096 or ECDSA P-256.",
		))
	}

	return cert, findings, nil
}

// ─── DNS Security Scanner ──────────────────────────────────────────────────

func (s *Scanner) scanDNSSecurity(ctx context.Context, domain string, asset *models.Asset) (*models.DNSSecurityResult, []*models.Finding, error) {
	result := &models.DNSSecurityResult{
		AssetID:      asset.ID,
		Domain:       domain,
		SPFStatus:    models.CheckNA,
		DKIMStatus:   models.CheckNA,
		DMARCStatus:  models.CheckNA,
		MTASTSStatus: models.CheckNA,
		DNSSECStatus: models.CheckNA,
	}

	var findings []*models.Finding
	c := new(dns.Client)
	c.Timeout = s.timeout

	// SPF check
	spfRecord := lookupTXT(c, domain, "v=spf1")
	if spfRecord != "" {
		result.SPFRecord = spfRecord
		result.SPFStatus = models.CheckPass
	} else {
		result.SPFStatus = models.CheckFail
		findings = append(findings, makeFinding(asset,
			fmt.Sprintf("SPF Record Missing — %s", domain),
			"No SPF record found. Domain is vulnerable to email spoofing and phishing attacks.",
			models.SevHigh, models.CatEmail, domain,
			`Add TXT record: "v=spf1 include:_spf.yourmailprovider.com ~all"`,
		))
	}

	// DMARC check
	dmarcRecord := lookupTXT(c, "_dmarc."+domain, "v=DMARC1")
	if dmarcRecord != "" {
		result.DMARCRecord = dmarcRecord
		result.DMARCStatus = models.CheckPass
		// Check policy strength
		if strings.Contains(dmarcRecord, "p=none") {
			result.DMARCStatus = models.CheckWarning
			result.DMARCPolicy = "none"
			findings = append(findings, makeFinding(asset,
				fmt.Sprintf("DMARC Policy is p=none — %s", domain),
				"DMARC is configured but policy=none doesn't protect against spoofing. Only monitors.",
				models.SevMedium, models.CatEmail, domain,
				`Change DMARC policy to p=quarantine or p=reject for actual protection.`,
			))
		} else if strings.Contains(dmarcRecord, "p=quarantine") {
			result.DMARCPolicy = "quarantine"
		} else if strings.Contains(dmarcRecord, "p=reject") {
			result.DMARCPolicy = "reject"
		}
	} else {
		result.DMARCStatus = models.CheckFail
		findings = append(findings, makeFinding(asset,
			fmt.Sprintf("DMARC Record Missing — %s", domain),
			"No DMARC record found. Without DMARC, spoofed emails using your domain may reach inboxes.",
			models.SevHigh, models.CatEmail, domain,
			`Add TXT record at _dmarc.`+domain+`: "v=DMARC1; p=quarantine; rua=mailto:dmarc@`+domain+`"`,
		))
	}

	// MTA-STS check
	mtaSTS := lookupTXT(c, "_mta-sts."+domain, "v=STSv1")
	if mtaSTS != "" {
		result.MTASTSStatus = models.CheckPass
	} else {
		result.MTASTSStatus = models.CheckNA
	}

	// DNSSEC check (DS record in parent zone)
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeDNSKEY)
	m.SetEdns0(4096, true)
	if r, _, err := c.ExchangeContext(ctx, m, "8.8.8.8:53"); err == nil && len(r.Answer) > 0 {
		result.DNSSECStatus = models.CheckPass
	}

	// Calculate overall score
	score := 0.0
	if result.SPFStatus == models.CheckPass {
		score += 30
	}
	if result.DMARCStatus == models.CheckPass {
		score += 40
	} else if result.DMARCStatus == models.CheckWarning {
		score += 20
	}
	if result.DKIMStatus == models.CheckPass {
		score += 20
	}
	if result.MTASTSStatus == models.CheckPass {
		score += 5
	}
	if result.DNSSECStatus == models.CheckPass {
		score += 5
	}
	result.OverallScore = score

	return result, findings, nil
}

// ─── Exposure Scanner ──────────────────────────────────────────────────────

var exposurePaths = []struct {
	path         string
	exposureType models.ExposureType
	title        string
	severity     models.Severity
	confidence   float64
}{
	{"/wp-admin", models.ExposureAdminPanel, "WordPress Admin Panel Exposed", models.SevCritical, 95},
	{"/wp-admin/", models.ExposureAdminPanel, "WordPress Admin Panel Exposed", models.SevCritical, 95},
	{"/admin", models.ExposureAdminPanel, "Admin Panel Exposed", models.SevCritical, 85},
	{"/administrator", models.ExposureAdminPanel, "Joomla Admin Panel Exposed", models.SevCritical, 90},
	{"/phpmyadmin", models.ExposureAdminPanel, "phpMyAdmin Exposed", models.SevCritical, 99},
	{"/phpMyAdmin", models.ExposureAdminPanel, "phpMyAdmin Exposed", models.SevCritical, 99},
	{"/pma", models.ExposureAdminPanel, "phpMyAdmin Exposed", models.SevCritical, 90},
	{"/.git/HEAD", models.ExposureConfigFile, "Git Repository Exposed", models.SevCritical, 100},
	{"/.env", models.ExposureConfigFile, ".env File Exposed", models.SevCritical, 99},
	{"/config.php", models.ExposureConfigFile, "PHP Config File Exposed", models.SevCritical, 90},
	{"/wp-config.php.bak", models.ExposureBackupFile, "WordPress Config Backup Exposed", models.SevCritical, 95},
	{"/debug", models.ExposureDebugPage, "Debug Page Exposed", models.SevHigh, 85},
	{"/debug/", models.ExposureDebugPage, "Debug Page Exposed", models.SevHigh, 85},
	{"/_debugbar", models.ExposureDebugPage, "Laravel Debugbar Exposed", models.SevHigh, 90},
	{"/telescope", models.ExposureDebugPage, "Laravel Telescope Exposed", models.SevHigh, 90},
	{"/adminer.php", models.ExposureAdminPanel, "Adminer DB Admin Exposed", models.SevCritical, 99},
	{"/server-status", models.ExposureInfoDisclosure, "Apache Server Status Exposed", models.SevMedium, 95},
	{"/server-info", models.ExposureInfoDisclosure, "Apache Server Info Exposed", models.SevMedium, 90},
	{"/api/swagger.json", models.ExposureInfoDisclosure, "Swagger API Docs Exposed", models.SevLow, 95},
	{"/swagger-ui.html", models.ExposureInfoDisclosure, "Swagger UI Exposed", models.SevLow, 90},
	{"/actuator", models.ExposureInfoDisclosure, "Spring Actuator Exposed", models.SevHigh, 90},
	{"/actuator/env", models.ExposureInfoDisclosure, "Spring Actuator Env Exposed", models.SevCritical, 95},
	{"/metrics", models.ExposureInfoDisclosure, "Metrics Endpoint Exposed", models.SevMedium, 80},
	{"/graphql", models.ExposureInfoDisclosure, "GraphQL Introspection Exposed", models.SevMedium, 80},
}

func (s *Scanner) scanExposures(ctx context.Context, target string, asset *models.Asset) ([]*models.Exposure, []*models.Finding) {
	base := strings.TrimRight(target, "/")
	var exposures []*models.Exposure
	var findings []*models.Finding

	for _, ep := range exposurePaths {
		checkURL := base + ep.path
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, checkURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", s.userAgent)

		resp, err := s.httpClient.Do(req)
		if err != nil {
			continue
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()

		// Only flag 200 OK responses (not 403/404/301)
		if resp.StatusCode != 200 {
			continue
		}

		exposure := &models.Exposure{
			AssetID:      asset.ID,
			AssetName:    asset.Name,
			ExposureType: ep.exposureType,
			Title:        ep.title,
			Description:  fmt.Sprintf("'%s' is publicly accessible at %s", ep.path, checkURL),
			URL:          checkURL,
			Severity:     ep.severity,
			Confidence:   ep.confidence,
			BusinessImpact: exposureImpact(ep.exposureType),
			IsActive:     true,
		}
		exposures = append(exposures, exposure)

		findings = append(findings, makeFinding(asset,
			ep.title,
			fmt.Sprintf("Exposure detected: '%s' returned HTTP 200. %s", ep.path, exposureDescription(ep.exposureType)),
			ep.severity, models.CatExposure, checkURL,
			exposureRemediation(ep.exposureType, ep.path),
		))
	}

	return exposures, findings
}

// ─── Helpers ──────────────────────────────────────────────────────────────

func makeFinding(asset *models.Asset, title, description string, sev models.Severity, cat models.Category, url, remediation string) *models.Finding {
	h := fmt.Sprintf("%x", md5.Sum([]byte(asset.ID+string(cat)+title)))
	return &models.Finding{
		AssetID:     asset.ID,
		AssetName:   asset.Name,
		Title:       title,
		Description: description,
		Severity:    sev,
		Status:      models.StatusOpen,
		Category:    cat,
		AffectedURL: url,
		Remediation: remediation,
		Confidence:  100,
		CVSSScore:   severityCVSS(sev),
		Hash:        h,
		FirstSeenAt: time.Now(),
		LastSeenAt:  time.Now(),
		CreatedAt:   time.Now(),
	}
}

func severityCVSS(sev models.Severity) float64 {
	switch sev {
	case models.SevCritical:
		return 9.0
	case models.SevHigh:
		return 7.5
	case models.SevMedium:
		return 5.0
	case models.SevLow:
		return 2.5
	default:
		return 0.0
	}
}

func calculateWebGrade(r *models.WebSecurityResult, issues []string) (float64, string) {
	score := 100.0
	if !r.HasHSTS {
		score -= 20
	}
	if !r.HasCSP {
		score -= 20
	}
	if !r.HasXFrameOptions {
		score -= 10
	}
	if !r.HasXContentTypeOptions {
		score -= 10
	}
	if !r.HasReferrerPolicy {
		score -= 5
	}
	if !r.HasPermissionsPolicy {
		score -= 5
	}
	if !r.CookiesSecure {
		score -= 10
	}
	if !r.HTTPToHTTPS {
		score -= 15
	}
	if r.ServerVersionDisclosed {
		score -= 5
	}
	if score < 0 {
		score = 0
	}
	grade := ""
	switch {
	case score >= 95:
		grade = "A+"
	case score >= 80:
		grade = "A"
	case score >= 65:
		grade = "B"
	case score >= 50:
		grade = "C"
	case score >= 35:
		grade = "D"
	default:
		grade = "F"
	}
	return score, grade
}

func lookupTXT(c *dns.Client, domain, prefix string) string {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeTXT)
	r, _, err := c.Exchange(m, "8.8.8.8:53")
	if err != nil {
		return ""
	}
	for _, ans := range r.Answer {
		if txt, ok := ans.(*dns.TXT); ok {
			record := strings.Join(txt.Txt, "")
			if strings.HasPrefix(record, prefix) {
				return record
			}
		}
	}
	return ""
}

func extractDomain(value string) string {
	value = strings.TrimPrefix(value, "https://")
	value = strings.TrimPrefix(value, "http://")
	if i := strings.Index(value, "/"); i != -1 {
		value = value[:i]
	}
	if h, _, err := net.SplitHostPort(value); err == nil {
		return h
	}
	return value
}

func containsVersionInfo(s string) bool {
	s = strings.ToLower(s)
	keywords := []string{"/", ".", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9"}
	hasSlash := strings.Contains(s, "/")
	hasDigit := false
	for _, k := range keywords[2:] {
		if strings.Contains(s, k) {
			hasDigit = true
			break
		}
	}
	return hasSlash && hasDigit
}

func tlsVersionString(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS10:
		return "TLS 1.0"
	default:
		return "Unknown"
	}
}

func quoteAll(ss []string) []string {
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = `"` + s + `"`
	}
	return out
}

func exposureImpact(t models.ExposureType) string {
	switch t {
	case models.ExposureAdminPanel:
		return "Full administrative access to the system"
	case models.ExposureConfigFile:
		return "Credential and secret exposure"
	case models.ExposureDebugPage:
		return "Application internals and stack traces exposed"
	case models.ExposureInfoDisclosure:
		return "Technology fingerprinting enables targeted attacks"
	default:
		return "Information exposure"
	}
}

func exposureDescription(t models.ExposureType) string {
	switch t {
	case models.ExposureAdminPanel:
		return "Admin panel is publicly accessible without network restriction."
	case models.ExposureConfigFile:
		return "Configuration file may contain secrets, API keys, or database credentials."
	case models.ExposureDebugPage:
		return "Debug interface exposes environment variables and application internals."
	default:
		return "Sensitive endpoint is publicly accessible."
	}
}

func exposureRemediation(t models.ExposureType, path string) string {
	switch t {
	case models.ExposureAdminPanel:
		return fmt.Sprintf("Restrict access to %s by IP allowlist via WAF/firewall. Change to non-default path.", path)
	case models.ExposureConfigFile:
		return fmt.Sprintf("Remove %s from web root immediately. Add to .htaccess deny rules or server config.", path)
	case models.ExposureDebugPage:
		return fmt.Sprintf("Disable debug mode in production environment. Block %s via web server config.", path)
	default:
		return fmt.Sprintf("Restrict access to %s or remove it from production.", path)
	}
}
