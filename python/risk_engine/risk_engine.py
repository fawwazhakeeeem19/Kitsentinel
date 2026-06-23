
"""
KitSentinel Python Intelligence Engine — Risk Correlation & Scoring
Consumes findings from SQLite and computes weighted risk scores.
"""

import json
import math
import sqlite3
import sys
import argparse
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from typing import Optional




SEVERITY_WEIGHTS = {
    "critical": 25.0,
    "high":     15.0,
    "medium":    7.0,
    "low":       2.0,
    "info":      0.5,
}

CATEGORY_MULTIPLIERS = {
    "exposure":           1.4,
    "tls":                1.2,
    "ssl_certificate":    1.2,
    "admin_panel":        1.5,
    "email_security":     1.1,
    "headers":            1.0,
    "csp_policy":         1.0,
    "cookies":            0.9,
    "info_disclosure":    0.8,
    "configuration":      1.0,
}

RECENCY_DECAY = {
    1:  1.0,   # same day
    3:  0.95,
    7:  0.9,
    14: 0.85,
    30: 0.75,
    90: 0.60,
}


@dataclass
class AssetRisk:
    asset_id: str
    asset_name: str
    finding_score: float
    exposure_score: float
    config_score: float
    recency_score: float
    composite_score: float
    risk_level: str
    trend: str
    trend_delta: float
    finding_count: int
    critical_count: int
    exposure_count: int


def recency_multiplier(first_seen: str) -> float:
    """Reduce weight for older findings that haven't been addressed."""
    try:
        dt = datetime.fromisoformat(first_seen.replace("Z", "+00:00"))
    except Exception:
        return 1.0
    age_days = (datetime.now() - dt.replace(tzinfo=None)).days
    for threshold in sorted(RECENCY_DECAY.keys(), reverse=True):
        if age_days >= threshold:
            return RECENCY_DECAY[threshold]
    return 1.0


def risk_level(score: float) -> str:
    if score >= 70: return "critical"
    if score >= 50: return "high"
    if score >= 25: return "medium"
    if score >  0:  return "low"
    return "none"


def calculate_asset_risk(conn: sqlite3.Connection, asset_id: str, asset_name: str) -> AssetRisk:
    cur = conn.cursor()


    cur.execute("""
        SELECT severity, category, first_seen_at, confidence
        FROM findings
        WHERE asset_id=? AND status='open'
    """, (asset_id,))
    findings = cur.fetchall()


    cur.execute("""
        SELECT severity, confidence
        FROM exposures
        WHERE asset_id=? AND is_active=1
    """, (asset_id,))
    exposures = cur.fetchall()


    finding_score = 0.0
    critical_count = 0
    for sev, cat, first_seen, confidence in findings:
        base = SEVERITY_WEIGHTS.get(sev, 2.0)
        cat_mult = CATEGORY_MULTIPLIERS.get(cat, 1.0)
        rec_mult = recency_multiplier(first_seen or "")
        conf_mult = (confidence or 100) / 100.0
        finding_score += base * cat_mult * rec_mult * conf_mult
        if sev == "critical":
            critical_count += 1

    finding_score = min(finding_score, 100.0)


    exposure_score = 0.0
    for sev, confidence in exposures:
        base = SEVERITY_WEIGHTS.get(sev, 5.0) * 1.5  # exposures weighted higher
        conf_mult = (confidence or 80) / 100.0
        exposure_score += base * conf_mult
    exposure_score = min(exposure_score, 100.0)


    categories = set(f[1] for f in findings)
    config_score = min(len(categories) * 10.0, 100.0)



    recency_scores = [recency_multiplier(f[2] or "") for f in findings]
    recency_avg = sum(recency_scores) / len(recency_scores) if recency_scores else 0
    recency_score = recency_avg * 100


    composite = (
        exposure_score * 0.40 +
        finding_score  * 0.35 +
        config_score   * 0.15 +
        recency_score  * 0.10
    )


    cur.execute("SELECT is_critical FROM assets WHERE id=?", (asset_id,))
    row = cur.fetchone()
    if row and row[0]:
        composite = min(composite * 1.25, 100.0)

    composite = round(composite, 2)

    return AssetRisk(
        asset_id=asset_id,
        asset_name=asset_name,
        finding_score=round(finding_score, 2),
        exposure_score=round(exposure_score, 2),
        config_score=round(config_score, 2),
        recency_score=round(recency_score, 2),
        composite_score=composite,
        risk_level=risk_level(composite),
        trend="stable",
        trend_delta=0.0,
        finding_count=len(findings),
        critical_count=critical_count,
        exposure_count=len(exposures),
    )


def calculate_trend(conn: sqlite3.Connection, asset_id: str, current_score: float) -> tuple[str, float]:
    """Compare current score to 7-day-ago snapshot."""
    cur = conn.cursor()
    week_ago = (datetime.now() - timedelta(days=7)).strftime("%Y-%m-%d")
    cur.execute("""
        SELECT risk_score FROM historical_metrics
        WHERE metric_date <= ? ORDER BY metric_date DESC LIMIT 1
    """, (week_ago,))
    row = cur.fetchone()
    if not row:
        return "stable", 0.0

    old_score = row[0]
    delta = round(current_score - old_score, 2)

    if delta > 3:
        return "degrading", delta
    if delta < -3:
        return "improving", delta
    return "stable", delta


def run(db_path: str, output_format: str = "json") -> None:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row

    cur = conn.cursor()
    cur.execute("SELECT id, name FROM assets ORDER BY name")
    assets = cur.fetchall()

    results = []
    org_total = 0.0

    for asset in assets:
        asset_risk = calculate_asset_risk(conn, asset["id"], asset["name"])
        trend, delta = calculate_trend(conn, asset["id"], asset_risk.composite_score)
        asset_risk.trend = trend
        asset_risk.trend_delta = delta
        results.append(asset_risk)
        org_total += asset_risk.composite_score


        conn.execute("""
            INSERT INTO risks (id, asset_id, asset_name, asset_risk_score,
                configuration_risk_score, exposure_risk_score, overall_score,
                risk_level, trend, trend_delta, calculated_at)
            VALUES (lower(hex(randomblob(16))), ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(id) DO UPDATE SET
                overall_score=excluded.overall_score,
                risk_level=excluded.risk_level,
                trend=excluded.trend,
                trend_delta=excluded.trend_delta,
                calculated_at=excluded.calculated_at
        """, (
            asset_risk.asset_id, asset_risk.asset_name,
            asset_risk.finding_score, asset_risk.config_score,
            asset_risk.exposure_score, asset_risk.composite_score,
            asset_risk.risk_level, asset_risk.trend, asset_risk.trend_delta,
        ))

    conn.commit()
    conn.close()

    org_score = round(org_total / len(results), 2) if results else 0.0
    output = {
        "generated_at": datetime.now().isoformat(),
        "org_risk_score": org_score,
        "org_risk_level": risk_level(org_score),
        "total_assets": len(results),
        "assets": [asdict(r) for r in results],
    }

    if output_format == "json":
        print(json.dumps(output, indent=2))
    else:

        print(f"\n  ORG RISK SCORE: {org_score:.1f}/100  [{risk_level(org_score).upper()}]")
        print(f"  {'─'*60}")
        for r in sorted(results, key=lambda x: x.composite_score, reverse=True)[:10]:
            print(f"  {r.asset_name:<30} {r.composite_score:>6.1f}  [{r.risk_level.upper():<8}]  {r.trend}")
        print()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="KitSentinel Risk Engine")
    parser.add_argument("db_path", help="Path to SQLite database")
    parser.add_argument("--format", choices=["json", "text"], default="json")
    args = parser.parse_args()
    run(args.db_path, args.format)
