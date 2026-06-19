from prometheus_client import Gauge, Counter, generate_latest, CONTENT_TYPE_LATEST
from fastapi import Response
from sqlalchemy import text

from database import get_db

domain_up = Gauge("domain_monitor_up", "Domain availability status, 1 means up, 0 means down", ["domain", "group", "agent", "region"])
domain_status_level = Gauge("domain_monitor_status_level", "Domain status level, ok=0 warning=1 error=2", ["domain", "group", "agent", "region"])
domain_http_code = Gauge("domain_monitor_http_status_code", "HTTP status code", ["domain", "group", "agent", "region"])
domain_response_time = Gauge("domain_monitor_response_time_ms", "HTTP response time in ms", ["domain", "group", "agent", "region"])
domain_ssl_days_left = Gauge("domain_monitor_ssl_days_left", "SSL certificate remaining days", ["domain", "group"])
domain_whois_days_left = Gauge("domain_monitor_whois_days_left", "WHOIS remaining days", ["domain", "group"])
domain_fail_count = Gauge("domain_monitor_fail_count", "Continuous failure count", ["domain", "group"])
domain_alert_total = Counter("domain_monitor_alert_total", "Alert count", ["domain", "group", "level"])
_metric_label_cache = {
    "domain_up": set(),
    "domain_status_level": set(),
    "domain_http_code": set(),
    "domain_response_time": set(),
    "domain_ssl_days_left": set(),
    "domain_whois_days_left": set(),
    "domain_fail_count": set(),
}

def update_domain_metrics(result: dict):
    domain = result.get("domain", "-")
    group = result.get("group_name", "default")
    agent = result.get("agent_name", "local")
    region = result.get("agent_region", "-")
    status = result.get("status", "error")
    domain_up.labels(domain, group, agent, region).set(1 if status == "ok" else 0)
    domain_status_level.labels(domain, group, agent, region).set(0 if status == "ok" else (1 if status == "warning" else 2))
    if result.get("http_code") is not None:
        domain_http_code.labels(domain, group, agent, region).set(result["http_code"])
    if result.get("response_time_ms") is not None:
        domain_response_time.labels(domain, group, agent, region).set(result["response_time_ms"])
    if result.get("ssl_days_left") is not None:
        domain_ssl_days_left.labels(domain, group).set(result["ssl_days_left"])
    if result.get("whois_days_left") is not None:
        domain_whois_days_left.labels(domain, group).set(result["whois_days_left"])
    if result.get("fail_count") is not None:
        domain_fail_count.labels(domain, group).set(result["fail_count"])

def _sync_metric_labels(cache_key: str, metric, current_labels: set[tuple]):
    previous_labels = _metric_label_cache.get(cache_key, set())
    for labels in previous_labels - current_labels:
        metric.remove(*labels)
    _metric_label_cache[cache_key] = current_labels

def sync_metrics_from_db():
    with get_db() as db:
        rows = db.execute(text("""
        SELECT
            d.domain,
            COALESCE(g.name, 'default') AS group_name,
            r.status,
            r.http_code,
            r.response_time_ms,
            r.ssl_days_left,
            r.whois_days_left,
            r.agent_name,
            r.agent_region,
            COALESCE(a.fail_count, 0) AS fail_count
        FROM domains d
        LEFT JOIN domain_groups g ON d.group_id=g.id
        LEFT JOIN check_results r ON r.id = (
            SELECT id FROM check_results
            WHERE domain_id=d.id AND is_summary=true
            ORDER BY id DESC
            LIMIT 1
        )
        LEFT JOIN alert_state a ON a.domain_id=d.id
        WHERE d.enabled=true
        ORDER BY d.id ASC
        """)).mappings().fetchall()

    current_up = set()
    current_status_level = set()
    current_http = set()
    current_response = set()
    current_ssl = set()
    current_whois = set()
    current_fail = set()

    for row in rows:
        if not row["status"]:
            continue
        domain = row["domain"] or "-"
        group = row["group_name"] or "default"
        agent = row["agent_name"] or "local"
        region = row["agent_region"] or "-"
        labels4 = (domain, group, agent, region)
        labels2 = (domain, group)

        current_up.add(labels4)
        domain_up.labels(*labels4).set(1 if row["status"] == "ok" else 0)
        current_status_level.add(labels4)
        domain_status_level.labels(*labels4).set(0 if row["status"] == "ok" else (1 if row["status"] == "warning" else 2))

        if row["http_code"] is not None:
            current_http.add(labels4)
            domain_http_code.labels(*labels4).set(row["http_code"])
        if row["response_time_ms"] is not None:
            current_response.add(labels4)
            domain_response_time.labels(*labels4).set(row["response_time_ms"])
        if row["ssl_days_left"] is not None:
            current_ssl.add(labels2)
            domain_ssl_days_left.labels(*labels2).set(row["ssl_days_left"])
        if row["whois_days_left"] is not None:
            current_whois.add(labels2)
            domain_whois_days_left.labels(*labels2).set(row["whois_days_left"])

        current_fail.add(labels2)
        domain_fail_count.labels(*labels2).set(row["fail_count"])

    _sync_metric_labels("domain_up", domain_up, current_up)
    _sync_metric_labels("domain_status_level", domain_status_level, current_status_level)
    _sync_metric_labels("domain_http_code", domain_http_code, current_http)
    _sync_metric_labels("domain_response_time", domain_response_time, current_response)
    _sync_metric_labels("domain_ssl_days_left", domain_ssl_days_left, current_ssl)
    _sync_metric_labels("domain_whois_days_left", domain_whois_days_left, current_whois)
    _sync_metric_labels("domain_fail_count", domain_fail_count, current_fail)

def metrics_response():
    sync_metrics_from_db()
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)
