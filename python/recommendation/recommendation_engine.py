
"""
KitSentinel Python Intelligence Engine — Recommendation Engine
Generates prioritized, actionable remediation recommendations from findings.
"""

import json
import sqlite3
import argparse
import uuid
from datetime import datetime


PRIORITY_MAP = {
    "critical": ("p1_critical", "P1 CRITICAL"),
    "high":     ("p2_high",     "P2 HIGH"),
    "medium":   ("p3_medium",   "P3 MEDIUM"),
    "low":      ("p4_low",      "P4 LOW"),
    "info":     ("p5_info",     "P5 INFO"),
}

CATEGORY_REMEDIATION = {
    "tls": {
        "explanation": "Weak TLS configuration allows downgrade and interception attacks.",
        "impact":      "MITM attacks, decryption of sensitive data in transit.",
        "effort":      "2-4 hours",
        "steps": [
            "Run: openssl s_client -connect {domain}:443 to audit current TLS",
            "Disable TLS 1.0 and TLS 1.1 in web server config",
            "Enable only TLS 1.2 and TLS 1.3",
            "Configure strong cipher suites (ECDHE+AES-GCM, ECDHE+CHACHA20)",
            "Set HSTS header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
            "Test with: https://www.ssllabs.com/ssltest/",
        ],
        "references": ["https://wiki.mozilla.org/Security/Server_Side_TLS"],
    },
    "headers": {
        "explanation": "Missing security headers leave browsers vulnerable to XSS, clickjacking, and MIME sniffing.",
        "impact":      "XSS, clickjacking, CSRF, data injection attacks against users.",
        "effort":      "1-2 hours",
        "steps": [
            "Add missing headers to web server or application middleware",
            "X-Content-Type-Options: nosniff",
            "X-Frame-Options: DENY",
            "Referrer-Policy: strict-origin-when-cross-origin",
            "Permissions-Policy: geolocation=(), microphone=(), camera=()",
            "Verify at: https://securityheaders.com",
        ],
        "references": ["https://owasp.org/www-project-secure-headers/"],
    },
    "csp_policy": {
        "explanation": "Content Security Policy prevents XSS and unauthorized resource loading.",
        "impact":      "XSS attacks, data exfiltration via malicious scripts.",
        "effort":      "4-8 hours",
        "steps": [
            "Start with CSP report-only: Content-Security-Policy-Report-Only: default-src 'self'",
            "Monitor violations via browser console or reporting endpoint",
            "Move all inline JS to external files",
            "Move all inline CSS to external files",
            "Whitelist legitimate CDN sources",
            "Enforce with: Content-Security-Policy: default-src 'self'",
            "Test at: https://csp-evaluator.withgoogle.com/",
        ],
        "references": ["https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"],
    },
    "email_security": {
        "explanation": "Missing SPF/DMARC/DKIM allows attackers to spoof your domain in emails.",
        "impact":      "Phishing attacks, business email compromise (BEC), brand damage.",
        "effort":      "1-3 hours",
        "steps": [
            "Add SPF TXT record: v=spf1 include:_spf.mailprovider.com ~all",
            "Configure DKIM with your mail provider",
            "Add DMARC TXT at _dmarc.yourdomain: v=DMARC1; p=none; rua=mailto:dmarc@yourdomain",
            "Monitor DMARC reports for 2-4 weeks",
            "Upgrade policy to p=quarantine then p=reject",
            "Test at: https://mxtoolbox.com/DMARC.aspx",
        ],
        "references": ["https://dmarc.org/wiki/FAQ"],
    },
    "exposure": {
        "explanation": "Publicly accessible sensitive endpoints allow unauthorized access to admin functions or data.",
        "impact":      "Full system compromise, data breach, credential theft.",
        "effort":      "30 minutes",
        "steps": [
            "Immediately verify: curl -I <exposed_url>",
            "Block via WAF rule or firewall ACL restricting to trusted IPs",
            "Remove or relocate the exposed file/endpoint",
            "Rotate any credentials that may have been exposed",
            "Review access logs for prior unauthorized access",
            "Add deny rule in web server config",
        ],
        "references": ["https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"],
    },
    "ssl_certificate": {
        "explanation": "Certificate issues cause browser warnings, connection failures, or MITM vulnerabilities.",
        "impact":      "Service disruption, loss of user trust, potential MITM attacks.",
        "effort":      "30 minutes - 2 hours",
        "steps": [
            "Check expiry: openssl s_client -connect domain:443 | openssl x509 -noout -dates",
            "Let's Encrypt renewal: sudo certbot renew --dry-run && sudo certbot renew",
            "Verify certbot timer: systemctl status certbot.timer",
            "Reload web server after renewal: systemctl reload nginx",
            "Set up monitoring: kitsentinel certificates tracks expiry automatically",
        ],
        "references": ["https://letsencrypt.org/docs/"],
    },
    "cookies": {
        "explanation": "Insecure cookie attributes allow session hijacking via XSS or network interception.",
        "impact":      "Session hijacking, account takeover, CSRF attacks.",
        "effort":      "1-2 hours",
        "steps": [
            "Set Secure flag on all cookies (requires HTTPS)",
            "Set HttpOnly flag to prevent JavaScript access",
            "Set SameSite=Strict or SameSite=Lax to prevent CSRF",
            "Use __Host- prefix for critical session cookies",
            "Set appropriate Max-Age for session expiry",
        ],
        "references": ["https://owasp.org/www-community/controls/SecureCookieAttribute"],
    },
}


def generate_recommendations(db_path: str, output_format: str = "json") -> None:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row

    cur = conn.cursor()
    cur.execute("""
        SELECT f.id, f.asset_id, f.asset_name, f.title, f.severity,
               f.category, f.remediation, f.affected_url, f.description
        FROM findings f
        WHERE f.status = 'open'
        ORDER BY CASE f.severity
            WHEN 'critical' THEN 1 WHEN 'high' THEN 2
            WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END,
            f.created_at ASC
    """)
    findings = cur.fetchall()

    recommendations = []
    seen_categories = {}  # deduplicate by category per asset

    for f in findings:
        cat = f["category"]
        sev = f["severity"]
        asset_id = f["asset_id"]


        dedup_key = f"{asset_id}:{cat}"
        if dedup_key in seen_categories:
            continue
        seen_categories[dedup_key] = True

        template = CATEGORY_REMEDIATION.get(cat, {})
        priority_key, priority_label = PRIORITY_MAP.get(sev, ("p4_low", "P4 LOW"))

        steps = template.get("steps", [f["remediation"]] if f["remediation"] else ["Review and remediate the issue."])

        domain = f["affected_url"] or f["asset_name"] or ""
        steps = [s.replace("{domain}", domain) for s in steps]

        rec = {
            "id": str(uuid.uuid4()),
            "finding_id": f["id"],
            "asset_id": asset_id,
            "asset_name": f["asset_name"],
            "title": f"Fix: {f['title']}",
            "explanation": template.get("explanation", f["description"] or ""),
            "impact": template.get("impact", "Potential security impact."),
            "priority": priority_key,
            "priority_label": priority_label,
            "steps": steps,
            "references": template.get("references", []),
            "estimated_effort": template.get("effort", "1-4 hours"),
            "category": cat,
            "is_completed": 0,
            "created_at": datetime.now().isoformat(),
        }
        recommendations.append(rec)


        conn.execute("""
            INSERT INTO recommendations
                (id, finding_id, asset_id, asset_name, title, explanation,
                 impact, priority, steps, references, estimated_effort, category, is_completed, created_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(id) DO UPDATE SET priority=excluded.priority
        """, (
            rec["id"], rec["finding_id"], rec["asset_id"], rec["asset_name"],
            rec["title"], rec["explanation"], rec["impact"], rec["priority"],
            json.dumps(rec["steps"]), json.dumps(rec["references"]),
            rec["estimated_effort"], rec["category"], rec["is_completed"], rec["created_at"],
        ))

    conn.commit()
    conn.close()

    output = {
        "generated_at": datetime.now().isoformat(),
        "total": len(recommendations),
        "by_priority": {
            "p1_critical": sum(1 for r in recommendations if r["priority"] == "p1_critical"),
            "p2_high":     sum(1 for r in recommendations if r["priority"] == "p2_high"),
            "p3_medium":   sum(1 for r in recommendations if r["priority"] == "p3_medium"),
            "p4_low":      sum(1 for r in recommendations if r["priority"] == "p4_low"),
        },
        "recommendations": recommendations,
    }

    if output_format == "json":
        print(json.dumps(output, indent=2))
    else:
        print(f"\n  RECOMMENDATIONS  ({len(recommendations)} actions)")
        print(f"  {'─'*60}")
        for r in recommendations:
            print(f"\n  [{r['priority_label']}] {r['title']}")
            print(f"  Asset    : {r['asset_name']}")
            print(f"  Effort   : {r['estimated_effort']}")
            print(f"  Impact   : {r['impact']}")
            print(f"  Steps    :")
            for i, step in enumerate(r["steps"][:4], 1):
                print(f"    {i}. {step}")
        print()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="KitSentinel Recommendation Engine")
    parser.add_argument("db_path", help="Path to SQLite database")
    parser.add_argument("--format", choices=["json", "text"], default="json")
    args = parser.parse_args()
    generate_recommendations(args.db_path, args.format)
