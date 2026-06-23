package recommendation

import (
	"context"
	"fmt"
	"strings"

	"github.com/kitsentinel/cli/internal/models"
	"github.com/kitsentinel/cli/internal/storage"
)

// Engine generates prioritized recommendations from findings.
type Engine struct {
	store *storage.Store
}

func NewEngine(store *storage.Store) *Engine {
	return &Engine{store: store}
}

// Generate creates recommendations for all open findings.
func (e *Engine) Generate(ctx context.Context) ([]*models.Recommendation, error) {
	findings, err := e.store.ListFindings(ctx, "")
	if err != nil {
		return nil, err
	}

	var recs []*models.Recommendation
	seen := map[string]bool{}

	for _, f := range findings {
		key := string(f.Category) + "|" + f.Title
		if seen[key] {
			continue // deduplicate same finding type
		}
		seen[key] = true

		rec := buildRecommendation(f)
		_ = e.store.UpsertRecommendation(ctx, rec)
		recs = append(recs, rec)
	}

	return recs, nil
}

func buildRecommendation(f *models.Finding) *models.Recommendation {
	rec := &models.Recommendation{
		FindingID: f.ID,
		AssetID:   f.AssetID,
		AssetName: f.AssetName,
		Title:     "Fix: " + f.Title,
		Priority:  findingPriority(f.Severity),
		Category:  string(f.Category),
	}

	switch f.Category {
	case models.CatTLS:
		rec.Explanation = "Your TLS configuration has weaknesses that allow attackers to intercept or tamper with encrypted communications."
		rec.Impact = "Attacker-in-the-middle (MITM) attacks, session hijacking, decryption of sensitive data."
		rec.EstimatedEffort = "2-4 hours"
		rec.Steps = formatSteps([]string{
			"Audit current TLS settings: `openssl s_client -connect " + f.AssetID + ":443`",
			"Disable TLS 1.0 and TLS 1.1 in your web server config",
			"Enable TLS 1.2 and TLS 1.3 only",
			"Configure strong cipher suites (ECDHE+AESGCM, ECDHE+CHACHA20)",
			"Test with: https://www.ssllabs.com/ssltest/",
			"Verify configuration with: `nmap --script ssl-enum-ciphers`",
		})
		rec.References = "https://wiki.mozilla.org/Security/Server_Side_TLS"

	case models.CatHeaders:
		rec.Explanation = "Security headers protect browsers from common web attacks like XSS, clickjacking, and MIME sniffing."
		rec.Impact = "XSS, clickjacking, CSRF, MIME confusion attacks against users."
		rec.EstimatedEffort = "1-2 hours"
		rec.Steps = formatSteps([]string{
			"Add the missing header(s) to your web server or application",
			"For Nginx: add in `server` block or `location` block",
			"For Apache: add in `.htaccess` or `httpd.conf`",
			"For application layer: add in middleware/response pipeline",
			f.Remediation,
			"Verify at: https://securityheaders.com",
		})
		rec.References = "https://owasp.org/www-project-secure-headers/"

	case models.CatCSP:
		rec.Explanation = "Content Security Policy prevents execution of malicious scripts and resource loading from untrusted origins."
		rec.Impact = "XSS attacks, data exfiltration via injected scripts, malvertising."
		rec.EstimatedEffort = "4-8 hours"
		rec.Steps = formatSteps([]string{
			"Start with report-only mode: `Content-Security-Policy-Report-Only: default-src 'self'`",
			"Monitor violations in browser console or report endpoint",
			"Identify and whitelist legitimate external resources",
			"Remove all inline scripts (move to .js files)",
			"Remove all inline styles (move to .css files)",
			"Graduate to enforced policy: `Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-{random}'`",
			"Test with: https://csp-evaluator.withgoogle.com/",
		})
		rec.References = "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"

	case models.CatEmail:
		rec.Explanation = "Email security records (SPF, DKIM, DMARC) prevent attackers from sending spoofed emails that appear to come from your domain."
		rec.Impact = "Phishing attacks targeting customers using your brand, business email compromise (BEC)."
		rec.EstimatedEffort = "1-3 hours"
		rec.Steps = emailSecuritySteps(f)
		rec.References = "https://dmarc.org/wiki/FAQ"

	case models.CatCertificate:
		rec.Explanation = "SSL certificate issues cause browser security warnings or complete connection failures."
		rec.Impact = "Service disruption, user trust erosion, potential MITM attacks."
		rec.EstimatedEffort = "30 minutes - 2 hours"
		rec.Steps = certSteps(f)
		rec.References = "https://letsencrypt.org/docs/"

	case models.CatExposure:
		rec.Explanation = "Exposed sensitive endpoints allow attackers to access administrative functions, source code, or configuration data."
		rec.Impact = "Full system compromise, data breach, credential theft, reputational damage."
		rec.EstimatedEffort = "30 minutes - 1 hour"
		rec.Steps = formatSteps([]string{
			"Immediately verify the exposure: `curl -I " + f.AffectedURL + "`",
			"Block access via firewall or web server ACL",
			"Remove or relocate the exposed file/endpoint",
			"Rotate any credentials that may have been exposed",
			"Review access logs for previous unauthorized access",
			"Add WAF rule to block similar paths",
		})
		rec.References = "https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure"

	case models.CatCookies:
		rec.Explanation = "Insecure cookie attributes allow attackers to steal session tokens via XSS or network interception."
		rec.Impact = "Session hijacking, account takeover, CSRF attacks."
		rec.EstimatedEffort = "1-2 hours"
		rec.Steps = formatSteps([]string{
			"Add `Secure` flag to all cookies (requires HTTPS)",
			"Add `HttpOnly` flag to prevent JavaScript access",
			"Set `SameSite=Strict` or `SameSite=Lax` to prevent CSRF",
			"Set `__Host-` prefix for additional security",
			"Review session cookie lifetime and set appropriate expiry",
		})
		rec.References = "https://owasp.org/www-community/controls/SecureCookieAttribute"

	default:
		rec.Explanation = f.Description
		rec.Impact = f.Impact
		rec.Steps = formatSteps([]string{f.Remediation})
		rec.EstimatedEffort = "1-4 hours"
	}

	return rec
}

func findingPriority(sev models.Severity) models.Priority {
	switch sev {
	case models.SevCritical:
		return models.PriorityP1Critical
	case models.SevHigh:
		return models.PriorityP2High
	case models.SevMedium:
		return models.PriorityP3Medium
	case models.SevLow:
		return models.PriorityP4Low
	default:
		return models.PriorityP5Informational
	}
}

func formatSteps(steps []string) string {
	var b strings.Builder
	b.WriteString("[")
	for i, s := range steps {
		if s == "" {
			continue
		}
		b.WriteString(fmt.Sprintf("%q", s))
		if i < len(steps)-1 {
			b.WriteString(",")
		}
	}
	b.WriteString("]")
	return b.String()
}

func emailSecuritySteps(f *models.Finding) string {
	title := strings.ToLower(f.Title)
	domain := f.AssetName

	if strings.Contains(title, "spf") {
		return formatSteps([]string{
			"Log in to your DNS provider (Cloudflare, Route53, etc.)",
			fmt.Sprintf(`Add TXT record for %s: "v=spf1 include:_spf.yourmailprovider.com ~all"`, domain),
			"Replace yourmailprovider.com with your actual email provider's SPF include",
			"Wait 1-24 hours for DNS propagation",
			"Verify: `dig TXT " + domain + " | grep spf`",
			"Test at: https://mxtoolbox.com/SPFRecordLookup.aspx",
		})
	}
	if strings.Contains(title, "dmarc") {
		return formatSteps([]string{
			"Log in to your DNS provider",
			fmt.Sprintf(`Add TXT record for _dmarc.%s: "v=DMARC1; p=none; rua=mailto:dmarc@%s"`, domain, domain),
			"Start with p=none (monitor only) to identify legitimate senders",
			"Analyze DMARC reports for 2-4 weeks",
			"Upgrade to p=quarantine then p=reject",
			"Test at: https://mxtoolbox.com/DMARC.aspx",
		})
	}
	return formatSteps([]string{f.Remediation})
}

func certSteps(f *models.Finding) string {
	title := strings.ToLower(f.Title)
	if strings.Contains(title, "expir") {
		return formatSteps([]string{
			"Check current cert status: `openssl s_client -connect " + f.AssetName + ":443 | openssl x509 -noout -dates`",
			"If using Let's Encrypt: `sudo certbot renew --dry-run` then `sudo certbot renew`",
			"If using commercial cert: generate new CSR and submit to CA",
			"Verify auto-renewal is working: `systemctl status certbot.timer`",
			"After renewal, reload web server: `sudo nginx -t && sudo systemctl reload nginx`",
			"Set up monitoring: `kitsentinel certificates` tracks expiry automatically",
		})
	}
	if strings.Contains(title, "self-signed") {
		return formatSteps([]string{
			"Install certbot: `sudo apt install certbot python3-certbot-nginx`",
			"Obtain Let's Encrypt cert: `sudo certbot --nginx -d " + f.AssetName + "`",
			"Verify auto-renewal: `sudo certbot renew --dry-run`",
			"Update web server to use new cert paths",
		})
	}
	return formatSteps([]string{f.Remediation})
}
