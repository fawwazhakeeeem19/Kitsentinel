
"""
KitSentinel Python Intelligence Engine — Trend Analytics
Computes historical trends, MTTR, and risk evolution over time.
"""

import json
import sqlite3
import argparse
from datetime import datetime, timedelta
from typing import Optional


def sparkline(values: list[float], width: int = 30) -> str:
    if not values:
        return ""
    bars = "▁▂▃▄▅▆▇█"
    mn, mx = min(values), max(values)
    if mn == mx:
        return bars[4] * min(len(values), width)
    result = ""
    step = max(1, len(values) // width)
    for i in range(0, min(len(values), width * step), step):
        v = values[i]
        idx = int((v - mn) / (mx - mn) * (len(bars) - 1))
        result += bars[idx]
    return result


def analyze(db_path: str, days: int, output_format: str = "json") -> None:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row

    start_date = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d")


    cur = conn.cursor()
    cur.execute("""
        SELECT * FROM historical_metrics
        WHERE metric_date >= ?
        ORDER BY metric_date ASC
    """, (start_date,))
    metrics = [dict(row) for row in cur.fetchall()]


    cur.execute("SELECT COUNT(*) as cnt FROM assets")
    total_assets = cur.fetchone()["cnt"]

    cur.execute("SELECT COUNT(*) as cnt FROM findings WHERE status='open'")
    total_findings = cur.fetchone()["cnt"]

    cur.execute("SELECT COUNT(*) as cnt FROM findings WHERE severity='critical' AND status='open'")
    critical = cur.fetchone()["cnt"]

    cur.execute("SELECT COUNT(*) as cnt FROM findings WHERE severity='high' AND status='open'")
    high = cur.fetchone()["cnt"]

    cur.execute("SELECT COUNT(*) as cnt FROM exposures WHERE is_active=1")
    exposures = cur.fetchone()["cnt"]


    current_score = 100.0 - critical * 8 - high * 4 - exposures * 10
    current_score = max(0.0, round(current_score, 2))

    prev_score = 0.0
    if metrics:
        prev_score = metrics[0].get("security_score", 0.0)

    delta = round(current_score - prev_score, 2)
    trend = "stable"
    if delta > 2:
        trend = "improving"
    elif delta < -2:
        trend = "degrading"


    labels = [m["metric_date"] for m in metrics]
    risk_scores = [m.get("risk_score", 0) for m in metrics]
    sec_scores = [m.get("security_score", 0) for m in metrics]
    finding_counts = [m.get("total_findings", 0) for m in metrics]
    new_findings = [m.get("new_findings", 0) for m in metrics]
    resolved = [m.get("resolved_findings", 0) for m in metrics]


    cur.execute("""
        SELECT asset_name, overall_score, risk_level, trend, trend_delta
        FROM risks ORDER BY overall_score DESC LIMIT 10
    """)
    top_risks = [dict(row) for row in cur.fetchall()]


    cur.execute("""
        SELECT category, COUNT(*) as cnt
        FROM findings WHERE status='open'
        GROUP BY category ORDER BY cnt DESC
    """)
    by_category = {row["category"]: row["cnt"] for row in cur.fetchall()}


    today = datetime.now().strftime("%Y-%m-%d")
    conn.execute("""
        INSERT INTO historical_metrics
            (id, metric_date, total_assets, total_findings, critical_findings,
             high_findings, total_exposures, security_score, risk_score, scan_count)
        VALUES (lower(hex(randomblob(16))), ?, ?, ?, ?, ?, ?, ?, ?, 1)
        ON CONFLICT(metric_date) DO UPDATE SET
            total_assets=excluded.total_assets,
            total_findings=excluded.total_findings,
            critical_findings=excluded.critical_findings,
            security_score=excluded.security_score,
            scan_count=scan_count+1
    """, (today, total_assets, total_findings, critical, high, exposures,
          current_score, 100 - current_score))
    conn.commit()
    conn.close()

    result = {
        "generated_at": datetime.now().isoformat(),
        "period_days": days,
        "current_score": current_score,
        "previous_score": prev_score,
        "score_delta": delta,
        "trend": trend,
        "total_assets": total_assets,
        "total_findings": total_findings,
        "critical_findings": critical,
        "active_exposures": exposures,
        "by_category": by_category,
        "top_risky_assets": top_risks,
        "time_series": {
            "labels": labels,
            "risk_scores": risk_scores,
            "security_scores": sec_scores,
            "total_findings": finding_counts,
            "new_findings": new_findings,
            "resolved_findings": resolved,
        },
        "sparklines": {
            "security_score": sparkline(sec_scores, 40),
            "risk_score": sparkline(risk_scores, 40),
            "findings": sparkline([float(f) for f in finding_counts], 40),
        },
    }

    if output_format == "json":
        print(json.dumps(result, indent=2))
    else:
        print(f"\n  ANALYTICS — {days}D TREND")
        print(f"  {'─' * 60}")
        print(f"  Security Score : {current_score:.1f}  (prev: {prev_score:.1f}  Δ{delta:+.1f})")
        print(f"  Trend          : {trend.upper()}")
        print(f"  Total Assets   : {total_assets}")
        print(f"  Open Findings  : {total_findings}  (critical: {critical})")
        print(f"  Exposures      : {exposures}")
        if sec_scores:
            print(f"\n  Score Trend    : {sparkline(sec_scores, 40)}")
        print()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="KitSentinel Analytics Engine")
    parser.add_argument("db_path", help="Path to SQLite database")
    parser.add_argument("--days", type=int, default=7, help="Period in days")
    parser.add_argument("--format", choices=["json", "text"], default="json")
    args = parser.parse_args()
    analyze(args.db_path, args.days, args.format)
