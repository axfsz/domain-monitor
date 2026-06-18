from prometheus_client import Gauge, Counter, generate_latest, CONTENT_TYPE_LATEST
from fastapi import Response

domain_up = Gauge("domain_monitor_up", "Domain availability status, 1 means up, 0 means down", ["domain", "group", "agent", "region"])
domain_http_code = Gauge("domain_monitor_http_status_code", "HTTP status code", ["domain", "group", "agent", "region"])
domain_response_time = Gauge("domain_monitor_response_time_ms", "HTTP response time in ms", ["domain", "group", "agent", "region"])
domain_ssl_days_left = Gauge("domain_monitor_ssl_days_left", "SSL certificate remaining days", ["domain", "group"])
domain_whois_days_left = Gauge("domain_monitor_whois_days_left", "WHOIS remaining days", ["domain", "group"])
domain_fail_count = Gauge("domain_monitor_fail_count", "Continuous failure count", ["domain", "group"])
domain_alert_total = Counter("domain_monitor_alert_total", "Alert count", ["domain", "group", "level"])

def update_domain_metrics(result: dict):
    domain = result.get("domain", "-")
    group = result.get("group_name", "default")
    agent = result.get("agent_name", "local")
    region = result.get("agent_region", "-")
    status = result.get("status", "error")
    domain_up.labels(domain, group, agent, region).set(1 if status == "ok" else 0)
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

def metrics_response():
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)
