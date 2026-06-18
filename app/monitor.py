import asyncio
from datetime import datetime, timedelta
from sqlalchemy import text
from config import SSL_EXPIRE_WARN_DAYS, WHOIS_EXPIRE_WARN_DAYS, AGENT_NAME, AGENT_REGION
from database import get_db
from checks import resolve_domain, check_port, check_ssl, check_http, check_whois_expire, ping_domain, parse_url_paths, parse_expected_statuses
from notify import send_notice
from metrics import update_domain_metrics, domain_alert_total

def in_silence_window(policy: dict) -> bool:
    start = policy.get("silence_start")
    end = policy.get("silence_end")
    if not start or not end:
        return False
    now = datetime.now().time()
    st = datetime.strptime(start, "%H:%M").time()
    et = datetime.strptime(end, "%H:%M").time()
    if st < et:
        return st <= now <= et
    return now >= st or now <= et

def save_result(result: dict):
    with get_db() as db:
        db.execute(text("""
        INSERT INTO check_results(domain_id, agent_name, agent_region, domain, group_name, url, url_path, is_summary, status, http_code,
        response_time_ms, resolved_ips, ssl_expire_at, ssl_days_left, whois_expire_at, whois_days_left, ping_ok, error)
        VALUES (:domain_id, :agent_name, :agent_region, :domain, :group_name, :url, :url_path, :is_summary, :status, :http_code, :response_time_ms,
        :resolved_ips, :ssl_expire_at, :ssl_days_left, :whois_expire_at, :whois_days_left, :ping_ok, :error)
        """), result)

def get_policy(group_id: int):
    with get_db() as db:
        p = db.execute(text("SELECT * FROM alert_policies WHERE group_id=:gid ORDER BY id DESC LIMIT 1"), {"gid": group_id}).mappings().fetchone()
        if not p:
            p = db.execute(text("SELECT * FROM alert_policies WHERE name='default' ORDER BY id DESC LIMIT 1")).mappings().fetchone()
        return dict(p) if p else {"fail_threshold": 3, "recover_threshold": 2, "escalation_minutes": 15}

async def process_alert(result: dict, policy: dict):
    domain_id = result["domain_id"]
    status = result["status"]
    current_error = result.get("error") or ""
    fail_threshold = int(policy.get("fail_threshold") or 3)
    recover_threshold = int(policy.get("recover_threshold") or 2)
    escalation_minutes = int(policy.get("escalation_minutes") or 15)
    should_alert = False
    recovered = False
    should_escalate = False
    with get_db() as db:
        state = db.execute(text("SELECT * FROM alert_state WHERE domain_id=:id"), {"id": domain_id}).mappings().fetchone()
        last_alert_status = state["last_alert_status"] if state else None
        old_fail_count = state["fail_count"] if state else 0
        old_success_count = state["success_count"] if state else 0
        old_first_failed_at = state["first_failed_at"] if state else None
        old_escalated = bool(state["escalated"]) if state else False
        if status in ("error", "warning"):
            fail_count = old_fail_count + 1
            success_count = 0
            first_failed_at = old_first_failed_at or datetime.now()
            if fail_count >= fail_threshold and last_alert_status != status:
                should_alert = True
            if last_alert_status in ("error", "warning") and not old_escalated and first_failed_at:
                if isinstance(first_failed_at, str):
                    first_failed_at = datetime.fromisoformat(first_failed_at)
                if datetime.now() - first_failed_at >= timedelta(minutes=escalation_minutes):
                    should_escalate = True
                    should_alert = True
        else:
            fail_count = 0
            success_count = old_success_count + 1
            first_failed_at = None
            if last_alert_status in ("error", "warning", "critical") and success_count >= recover_threshold:
                should_alert = True
                recovered = True
        if should_alert and not recovered and status == "warning" and in_silence_window(policy):
            should_alert = False
        new_last_alert_status = last_alert_status
        if should_alert:
            new_last_alert_status = "ok" if recovered else ("critical" if should_escalate else status)
        db.execute(text("""
        INSERT INTO alert_state(domain_id, current_status, fail_count, success_count, last_alert_status,
        last_alert_at, first_failed_at, escalated, last_error, updated_at)
        VALUES (:domain_id, :current_status, :fail_count, :success_count, :last_alert_status,
        :last_alert_at, :first_failed_at, :escalated, :last_error, CURRENT_TIMESTAMP)
        ON CONFLICT (domain_id) DO UPDATE SET
          current_status=excluded.current_status,
          fail_count=excluded.fail_count,
          success_count=excluded.success_count,
          last_alert_status=excluded.last_alert_status,
          last_alert_at=excluded.last_alert_at,
          first_failed_at=excluded.first_failed_at,
          escalated=excluded.escalated,
          last_error=excluded.last_error,
          updated_at=CURRENT_TIMESTAMP
        """), {
            "domain_id": domain_id,
            "current_status": status,
            "fail_count": fail_count,
            "success_count": success_count,
            "last_alert_status": new_last_alert_status,
            "last_alert_at": datetime.now() if should_alert else (state["last_alert_at"] if state else None),
            "first_failed_at": first_failed_at,
            "escalated": True if should_escalate else (False if recovered else old_escalated),
            "last_error": current_error,
        })
        result["fail_count"] = fail_count
    update_domain_metrics(result)
    if should_alert:
        if should_escalate:
            result["alert_level"] = "critical"
            result["error"] = f"[升级告警] {result.get('error') or ''}"
        domain_alert_total.labels(result.get("domain", "-"), result.get("group_name", "default"), result.get("alert_level", status)).inc()
        await send_notice(result, recovered=recovered)

def _base_result(row, status="ok"):
    return {
        "domain_id": row["id"], "domain": row["domain"], "group_name": row.get("group_name") or "default",
        "tags": row.get("tags") or "",
        "agent_name": AGENT_NAME, "agent_region": AGENT_REGION,
        "url": "", "url_path": "/", "is_summary": True,
        "status": status, "http_code": None, "response_time_ms": None,
        "resolved_ips": "", "ssl_expire_at": None, "ssl_days_left": None,
        "whois_expire_at": None, "whois_days_left": None,
        "ping_ok": None, "error": None,
        "urls_checked": 0,
    }

async def check_one_domain(row):
    row = dict(row)
    domain = row["domain"]
    protocol = row.get("protocol") or "https"
    port = int(row.get("port") or (443 if protocol == "https" else 80))
    expected = parse_expected_statuses(row.get("expected_statuses"))
    keyword = row.get("keyword") or ""
    result = _base_result(row)
    errors = []
    worst = "ok"
    try:
        if row.get("check_dns", True):
            ips = resolve_domain(domain)
            result["resolved_ips"] = ",".join(ips)
        if row.get("check_ping", True):
            result["ping_ok"], _ = ping_domain(domain)
        if row.get("check_http", True):
            check_port(domain, port)
            paths = parse_url_paths(row.get("url_paths") or "/")
            response_times = []
            first_code = None
            for path in paths:
                url = f"{protocol}://{domain}{path}" if port in (80, 443) else f"{protocol}://{domain}:{port}{path}"
                item = _base_result(row)
                item.update({"url": url, "url_path": path, "is_summary": False})
                try:
                    code, rt, keyword_ok = await check_http(url, keyword=keyword)
                    item["http_code"] = code
                    item["response_time_ms"] = rt
                    response_times.append(rt)
                    if first_code is None:
                        first_code = code
                    if code not in expected:
                        item["status"] = "error" if code >= 500 or code == 0 else "warning"
                        item["error"] = f"URL {path} 状态码 {code} 不在期望 {sorted(expected)}"
                    elif keyword and not keyword_ok:
                        item["status"] = "warning"
                        item["error"] = f"URL {path} 未匹配关键字：{keyword}"
                    else:
                        item["status"] = "ok"
                except Exception as exc:
                    item["status"] = "error"
                    item["error"] = f"URL {path} 检测失败：{exc}"
                if item["status"] != "ok":
                    errors.append(item["error"])
                    if item["status"] == "error":
                        worst = "error"
                    elif worst != "error":
                        worst = "warning"
                save_result(item)
            result["urls_checked"] = len(paths)
            result["http_code"] = first_code
            result["response_time_ms"] = max(response_times) if response_times else None
        if row.get("check_ssl", True) and (protocol == "https" or port == 443):
            result["ssl_expire_at"], result["ssl_days_left"] = check_ssl(domain, port)
            if result["ssl_days_left"] < 0:
                worst = "error"
                errors.append(f"SSL 证书已过期 {-result['ssl_days_left']} 天")
            elif result["ssl_days_left"] <= SSL_EXPIRE_WARN_DAYS and worst == "ok":
                worst = "warning"
                errors.append(f"SSL 证书即将过期，剩余 {result['ssl_days_left']} 天")
        if row.get("check_whois", True):
            result["whois_expire_at"], result["whois_days_left"], whois_error = check_whois_expire(domain)
            if result["whois_days_left"] is not None:
                if result["whois_days_left"] < 0:
                    worst = "error"
                    errors.append(f"域名注册已过期 {-result['whois_days_left']} 天")
                elif result["whois_days_left"] <= WHOIS_EXPIRE_WARN_DAYS and worst == "ok":
                    worst = "warning"
                    errors.append(f"域名注册即将过期，剩余 {result['whois_days_left']} 天")
        result["status"] = worst
        result["error"] = "; ".join(errors[:8]) if errors else None
    except Exception as e:
        result["status"] = "error"
        result["error"] = str(e)
    save_result(result)
    await process_alert(result, get_policy(row.get("group_id")))
    return result

async def check_all_domains():
    with get_db() as db:
        rows = db.execute(text("""
        SELECT d.*, g.name AS group_name FROM domains d
        LEFT JOIN domain_groups g ON d.group_id=g.id
        WHERE d.enabled=true
        ORDER BY d.id ASC
        """)).mappings().fetchall()
    if not rows:
        return []
    return await asyncio.gather(*(check_one_domain(dict(r)) for r in rows))

def latest_summary_rows():
    with get_db() as db:
        rows = db.execute(text("""
        SELECT d.*, g.name AS group_name, r.status, r.http_code, r.response_time_ms, r.resolved_ips,
               r.ssl_expire_at, r.ssl_days_left, r.whois_expire_at, r.whois_days_left, r.ping_ok, r.error, r.checked_at
        FROM domains d
        LEFT JOIN domain_groups g ON d.group_id=g.id
        LEFT JOIN check_results r ON r.id = (
            SELECT id FROM check_results WHERE domain_id=d.id AND is_summary=true ORDER BY id DESC LIMIT 1
        )
        ORDER BY d.id DESC
        """)).mappings().fetchall()
        return [dict(r) for r in rows]

def build_daily_summary():
    rows = latest_summary_rows()
    bad = [r for r in rows if r.get("status") in ("warning", "error")]
    return {
        "date": datetime.now().strftime("%Y-%m-%d"),
        "total": len(rows),
        "ok": len([r for r in rows if r.get("status") == "ok"]),
        "warning": len([r for r in rows if r.get("status") == "warning"]),
        "error": len([r for r in rows if r.get("status") == "error"]),
        "ssl_soon": len([r for r in rows if r.get("ssl_days_left") is not None and r.get("ssl_days_left") <= SSL_EXPIRE_WARN_DAYS]),
        "whois_soon": len([r for r in rows if r.get("whois_days_left") is not None and r.get("whois_days_left") <= WHOIS_EXPIRE_WARN_DAYS]),
        "bad": bad,
    }
