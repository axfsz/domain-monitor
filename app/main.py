import asyncio
from fastapi import FastAPI, Request, Form, Depends
from fastapi.responses import RedirectResponse, PlainTextResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from sqlalchemy import text
from urllib.parse import quote
from config import APP_NAME, DEFAULT_EXPECTED_STATUS
from database import init_db, get_db
from auth import verify_password, create_session, COOKIE_NAME, get_current_user, ensure_admin_user, hash_password, require_admin
from monitor import check_one_domain, check_all_domains, latest_summary_rows, build_daily_summary
from notify import send_daily_report
from checks import parse_url_paths
from metrics import metrics_response

app = FastAPI(title=APP_NAME)
templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory="static"), name="static")

def normalize_domain_input(raw: str, default_protocol: str, default_port: int, default_paths: str = "/"):
    raw = (raw or "").strip()
    if not raw:
        return None
    raw = raw.split("#", 1)[0].strip()
    if not raw:
        return None
    parts = [x.strip() for x in raw.replace("\t", ",").split(",") if x.strip()]
    first = parts[0]
    protocol = default_protocol
    port = default_port
    domain = first
    paths = default_paths or "/"
    if "://" in domain:
        protocol, rest = domain.split("://", 1)
        host_and_path = rest
        host = host_and_path.split("/", 1)[0]
        maybe_path = "/" + host_and_path.split("/", 1)[1] if "/" in host_and_path else "/"
        domain = host
        paths = maybe_path
    else:
        if "/" in domain:
            host, maybe_path = domain.split("/", 1)
            domain = host
            paths = "/" + maybe_path
    if ":" in domain:
        host, maybe_port = domain.rsplit(":", 1)
        if maybe_port.isdigit():
            domain = host
            port = int(maybe_port)
    if len(parts) >= 2 and parts[1] in ["http", "https"]:
        protocol = parts[1]
    if len(parts) >= 3 and parts[2].isdigit():
        port = int(parts[2])
    if len(parts) >= 4:
        paths = parts[3]
    domain = domain.strip().lower().strip(".")
    if not domain or " " in domain:
        return None
    return {"domain": domain, "protocol": protocol, "port": port, "url_paths": paths}

def audit(username: str, action: str, detail: str):
    try:
        with get_db() as db:
            db.execute(text("INSERT INTO audit_logs(username, action, detail) VALUES (:u,:a,:d)"), {"u": username, "a": action, "d": detail})
    except Exception as e:
        print(f"audit warning: {e}", flush=True)

@app.on_event("startup")
def startup():
    init_db()
    ensure_admin_user()

@app.get("/healthz")
def healthz():
    return {"status": "ok"}

@app.get("/metrics")
def metrics():
    return metrics_response()

@app.get("/api/domains")
def api_domains(user=Depends(get_current_user)):
    return latest_summary_rows()

@app.get("/login")
def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.post("/login")
def login(username: str = Form(...), password: str = Form(...)):
    with get_db() as db:
        user = db.execute(text("SELECT * FROM users WHERE username=:u AND enabled=true"), {"u": username}).mappings().fetchone()
    if not user or not verify_password(password, user["password_hash"]):
        return RedirectResponse("/login?error=1", status_code=302)
    response = RedirectResponse("/", status_code=302)
    response.set_cookie(COOKIE_NAME, create_session(user["id"]), httponly=True, max_age=86400, samesite="lax")
    return response

@app.get("/logout")
def logout():
    response = RedirectResponse("/login", status_code=302)
    response.delete_cookie(COOKIE_NAME)
    return response

@app.get("/")
def index(request: Request, bulk_msg: str = "", q: str = "", group_id: str = "", tag: str = "", user=Depends(get_current_user)):
    with get_db() as db:
        groups = db.execute(text("SELECT * FROM domain_groups ORDER BY id")).mappings().fetchall()
        where = []
        params = {}
        if q:
            where.append("d.domain LIKE :q")
            params["q"] = f"%{q}%"
        if group_id:
            where.append("CAST(d.group_id AS TEXT)=:gid")
            params["gid"] = group_id
        if tag:
            where.append("d.tags LIKE :tag")
            params["tag"] = f"%{tag}%"
        where_sql = "WHERE " + " AND ".join(where) if where else ""
        domains = db.execute(text(f"""
        SELECT d.*, g.name AS group_name, r.status, r.http_code, r.response_time_ms, r.resolved_ips,
               r.ssl_expire_at, r.ssl_days_left, r.whois_expire_at, r.whois_days_left, r.ping_ok, r.error, r.checked_at
        FROM domains d
        LEFT JOIN domain_groups g ON d.group_id=g.id
        LEFT JOIN check_results r ON r.id = (SELECT id FROM check_results WHERE domain_id=d.id AND is_summary=true ORDER BY id DESC LIMIT 1)
        {where_sql}
        ORDER BY d.id DESC
        """), params).mappings().fetchall()
    total = len(domains)
    ok = len([d for d in domains if d["status"] == "ok"])
    warning = len([d for d in domains if d["status"] == "warning"])
    error = len([d for d in domains if d["status"] == "error"])
    return templates.TemplateResponse("index.html", {"request": request, "user": user, "domains": domains, "groups": groups, "total": total, "ok": ok, "warning": warning, "error": error, "bulk_msg": bulk_msg, "q": q, "group_id": group_id, "tag": tag, "default_expected": DEFAULT_EXPECTED_STATUS})

@app.post("/domains/add")
def add_domain(domain: str = Form(...), protocol: str = Form("https"), port: int = Form(443), group_id: int = Form(...), remark: str = Form(""), tags: str = Form(""), url_paths: str = Form("/"), expected_statuses: str = Form(DEFAULT_EXPECTED_STATUS), keyword: str = Form(""), user=Depends(get_current_user)):
    with get_db() as db:
        db.execute(text("""
        INSERT INTO domains(domain, protocol, port, group_id, remark, tags, url_paths, expected_statuses, keyword, enabled)
        VALUES (:d,:p,:port,:gid,:r,:tags,:paths,:expected,:keyword,true)
        """), {"d": domain.strip().lower(), "p": protocol, "port": port, "gid": group_id, "r": remark, "tags": tags, "paths": url_paths or "/", "expected": expected_statuses or DEFAULT_EXPECTED_STATUS, "keyword": keyword})
    audit(user["username"], "add_domain", domain)
    return RedirectResponse("/", status_code=302)

@app.post("/domains/bulk-add")
def bulk_add_domains(domains_text: str = Form(...), protocol: str = Form("https"), port: int = Form(443), group_id: int = Form(...), remark: str = Form(""), tags: str = Form(""), url_paths: str = Form("/"), expected_statuses: str = Form(DEFAULT_EXPECTED_STATUS), keyword: str = Form(""), user=Depends(get_current_user)):
    lines = domains_text.splitlines()
    added = skipped = invalid = 0
    seen = set()
    with get_db() as db:
        for line in lines:
            item = normalize_domain_input(line, protocol, port, url_paths)
            if not item:
                invalid += 1 if line.strip() and not line.strip().startswith("#") else 0
                continue
            key = item["domain"]
            if key in seen:
                skipped += 1
                continue
            seen.add(key)
            exists = db.execute(text("SELECT id FROM domains WHERE domain=:d LIMIT 1"), {"d": key}).fetchone()
            if exists:
                skipped += 1
                continue
            db.execute(text("""
            INSERT INTO domains(domain, protocol, port, group_id, remark, tags, url_paths, expected_statuses, keyword, enabled)
            VALUES (:d, :p, :port, :gid, :r, :tags, :paths, :expected, :keyword, true)
            """), {"d": key, "p": item["protocol"], "port": item["port"], "gid": group_id, "r": remark, "tags": tags, "paths": item.get("url_paths") or url_paths or "/", "expected": expected_statuses or DEFAULT_EXPECTED_STATUS, "keyword": keyword})
            added += 1
    msg = f"批量添加完成：新增 {added} 个，跳过重复 {skipped} 个，无效 {invalid} 行"
    audit(user["username"], "bulk_add", msg)
    return RedirectResponse(f"/?bulk_msg={quote(msg)}", status_code=302)

@app.post("/domains/bulk-action")
async def bulk_action(domain_ids: list[int] = Form(default=[]), action: str = Form(...), group_id: str = Form(""), tags: str = Form(""), remark: str = Form(""), protocol: str = Form(""), port: str = Form(""), url_paths: str = Form(""), expected_statuses: str = Form(""), keyword: str = Form(""), user=Depends(get_current_user)):
    if not domain_ids:
        return RedirectResponse(f"/?bulk_msg={quote('未选择任何域名')}", status_code=302)
    checked = 0
    with get_db() as db:
        if action == "delete":
            for did in domain_ids:
                db.execute(text("DELETE FROM check_results WHERE domain_id=:id"), {"id": did})
                db.execute(text("DELETE FROM alert_state WHERE domain_id=:id"), {"id": did})
                db.execute(text("DELETE FROM domains WHERE id=:id"), {"id": did})
        elif action == "enable":
            db.execute(text("UPDATE domains SET enabled=true WHERE id = ANY(:ids)"), {"ids": domain_ids}) if False else None
            for did in domain_ids: db.execute(text("UPDATE domains SET enabled=true WHERE id=:id"), {"id": did})
        elif action == "disable":
            for did in domain_ids: db.execute(text("UPDATE domains SET enabled=false WHERE id=:id"), {"id": did})
        elif action == "set_tags":
            for did in domain_ids: db.execute(text("UPDATE domains SET tags=:tags WHERE id=:id"), {"tags": tags, "id": did})
        elif action == "append_tags":
            for did in domain_ids: db.execute(text("UPDATE domains SET tags=COALESCE(tags,'') || CASE WHEN COALESCE(tags,'')='' THEN '' ELSE ',' END || :tags WHERE id=:id"), {"tags": tags, "id": did})
        elif action == "edit":
            updates = []
            params = {}
            if group_id: updates.append("group_id=:group_id"); params["group_id"] = int(group_id)
            if remark: updates.append("remark=:remark"); params["remark"] = remark
            if protocol: updates.append("protocol=:protocol"); params["protocol"] = protocol
            if port: updates.append("port=:port"); params["port"] = int(port)
            if url_paths: updates.append("url_paths=:url_paths"); params["url_paths"] = url_paths
            if expected_statuses: updates.append("expected_statuses=:expected_statuses"); params["expected_statuses"] = expected_statuses
            if keyword != "": updates.append("keyword=:keyword"); params["keyword"] = keyword
            if tags: updates.append("tags=:tags"); params["tags"] = tags
            if updates:
                for did in domain_ids:
                    params["id"] = did
                    db.execute(text(f"UPDATE domains SET {', '.join(updates)} WHERE id=:id"), params)
    if action == "check":
        with get_db() as db:
            rows = db.execute(text("""
            SELECT d.*, g.name AS group_name FROM domains d LEFT JOIN domain_groups g ON d.group_id=g.id
            WHERE d.id IN :ids
            """), {"ids": tuple(domain_ids)}).mappings().fetchall() if False else []
            rows = []
            for did in domain_ids:
                r = db.execute(text("SELECT d.*, g.name AS group_name FROM domains d LEFT JOIN domain_groups g ON d.group_id=g.id WHERE d.id=:id"), {"id": did}).mappings().fetchone()
                if r:
                    item = dict(r)
                    item["trigger_source"] = "manual"
                    rows.append(item)
        for r in rows:
            await check_one_domain(r, notify=False)
            checked += 1
    msg = f"批量操作完成：动作 {action}，数量 {len(domain_ids)}" + (f"，已检测 {checked}" if checked else "")
    audit(user["username"], "bulk_action", msg)
    return RedirectResponse(f"/?bulk_msg={quote(msg)}", status_code=302)

@app.post("/domains/delete/{domain_id}")
def delete_domain(domain_id: int, user=Depends(get_current_user)):
    with get_db() as db:
        db.execute(text("DELETE FROM check_results WHERE domain_id=:id"), {"id": domain_id})
        db.execute(text("DELETE FROM alert_state WHERE domain_id=:id"), {"id": domain_id})
        db.execute(text("DELETE FROM domains WHERE id=:id"), {"id": domain_id})
    audit(user["username"], "delete_domain", str(domain_id))
    return RedirectResponse("/", status_code=302)

@app.post("/domains/toggle/{domain_id}")
def toggle_domain(domain_id: int, user=Depends(get_current_user)):
    with get_db() as db:
        db.execute(text("UPDATE domains SET enabled = NOT enabled WHERE id=:id"), {"id": domain_id})
    return RedirectResponse("/", status_code=302)

@app.post("/domains/check/{domain_id}")
async def manual_check(domain_id: int, user=Depends(get_current_user)):
    with get_db() as db:
        row = db.execute(text("SELECT d.*, g.name AS group_name FROM domains d LEFT JOIN domain_groups g ON d.group_id=g.id WHERE d.id=:id"), {"id": domain_id}).mappings().fetchone()
    if row:
        item = dict(row)
        item["trigger_source"] = "manual"
        await check_one_domain(item, notify=False)
    return RedirectResponse("/", status_code=302)

@app.post("/domains/check-all")
async def manual_check_all(user=Depends(get_current_user)):
    results = await check_all_domains(notify=False)
    msg = f"全量检测完成：{len(results)} 个域名"
    return RedirectResponse(f"/?bulk_msg={quote(msg)}", status_code=302)

@app.post("/reports/daily/send")
async def manual_daily_report(user=Depends(get_current_user)):
    summary = build_daily_summary()
    await send_daily_report(summary)
    return RedirectResponse(f"/?bulk_msg={quote('每日巡检报告已发送')}", status_code=302)

@app.get("/domains/{domain_id}")
def domain_detail(request: Request, domain_id: int, user=Depends(get_current_user)):
    with get_db() as db:
        domain = db.execute(text("SELECT d.*, g.name AS group_name FROM domains d LEFT JOIN domain_groups g ON d.group_id=g.id WHERE d.id=:id"), {"id": domain_id}).mappings().fetchone()
        results = db.execute(text("SELECT * FROM check_results WHERE domain_id=:id ORDER BY id DESC LIMIT 300"), {"id": domain_id}).mappings().fetchall()
    return templates.TemplateResponse("domain_detail.html", {"request": request, "user": user, "domain": domain, "results": results, "paths": parse_url_paths(domain["url_paths"] if domain else "/")})

@app.get("/domains/{domain_id}/edit")
def edit_domain_page(request: Request, domain_id: int, user=Depends(get_current_user)):
    with get_db() as db:
        domain = db.execute(text("SELECT * FROM domains WHERE id=:id"), {"id": domain_id}).mappings().fetchone()
        groups = db.execute(text("SELECT * FROM domain_groups ORDER BY id")).mappings().fetchall()
    if not domain:
        return RedirectResponse(f"/?bulk_msg={quote('域名不存在')}", status_code=302)
    return templates.TemplateResponse("domain_edit.html", {"request": request, "user": user, "domain": domain, "groups": groups, "default_expected": DEFAULT_EXPECTED_STATUS})

@app.post("/domains/{domain_id}/edit")
def update_domain(domain_id: int, domain: str = Form(...), protocol: str = Form("https"), port: int = Form(443), group_id: int = Form(...), remark: str = Form(""), tags: str = Form(""), url_paths: str = Form("/"), expected_statuses: str = Form(DEFAULT_EXPECTED_STATUS), keyword: str = Form(""), enabled: str = Form("1"), user=Depends(get_current_user)):
    enabled_bool = enabled in ["1", "true", "on", "yes"]
    with get_db() as db:
        db.execute(text("""
        UPDATE domains
        SET domain=:domain, protocol=:protocol, port=:port, group_id=:group_id, remark=:remark,
            tags=:tags, url_paths=:url_paths, expected_statuses=:expected_statuses, keyword=:keyword, enabled=:enabled
        WHERE id=:id
        """), {"domain": domain.strip().lower().strip('.'), "protocol": protocol, "port": port, "group_id": group_id, "remark": remark, "tags": tags, "url_paths": url_paths or '/', "expected_statuses": expected_statuses or DEFAULT_EXPECTED_STATUS, "keyword": keyword, "enabled": enabled_bool, "id": domain_id})
    audit(user["username"], "edit_domain", f"id={domain_id}, domain={domain}")
    return RedirectResponse(f"/?bulk_msg={quote('域名已更新')}", status_code=302)

@app.get("/admin")
def admin_page(request: Request, user=Depends(get_current_user)):
    require_admin(user)
    with get_db() as db:
        users = db.execute(text("SELECT id, username, role, enabled, created_at FROM users ORDER BY id")).mappings().fetchall()
        groups = db.execute(text("SELECT * FROM domain_groups ORDER BY id")).mappings().fetchall()
        policies = db.execute(text("SELECT p.*, g.name AS group_name FROM alert_policies p LEFT JOIN domain_groups g ON p.group_id=g.id ORDER BY p.id")).mappings().fetchall()
        audits = db.execute(text("SELECT * FROM audit_logs ORDER BY id DESC LIMIT 100")).mappings().fetchall()
    return templates.TemplateResponse("admin.html", {"request": request, "user": user, "users": users, "groups": groups, "policies": policies, "audits": audits})

@app.post("/admin/users/add")
def add_user(username: str = Form(...), password: str = Form(...), role: str = Form("user"), user=Depends(get_current_user)):
    require_admin(user)
    with get_db() as db:
        db.execute(text("INSERT INTO users(username, password_hash, role, enabled) VALUES (:u,:p,:r,true)"), {"u": username, "p": hash_password(password), "r": role})
    return RedirectResponse("/admin", status_code=302)

@app.post("/admin/groups/add")
def add_group(name: str = Form(...), description: str = Form(""), user=Depends(get_current_user)):
    require_admin(user)
    with get_db() as db:
        db.execute(text("INSERT INTO domain_groups(name, description) VALUES (:n,:d)"), {"n": name, "d": description})
    return RedirectResponse("/admin", status_code=302)

@app.post("/admin/policies/add")
def add_policy(name: str = Form(...), group_id: int = Form(...), fail_threshold: int = Form(3), recover_threshold: int = Form(2), silence_start: str = Form(""), silence_end: str = Form(""), escalation_minutes: int = Form(15), user=Depends(get_current_user)):
    require_admin(user)
    with get_db() as db:
        db.execute(text("""
        INSERT INTO alert_policies(name, group_id, fail_threshold, recover_threshold, silence_start, silence_end, escalation_minutes)
        VALUES (:n,:gid,:f,:r,:ss,:se,:em)
        """), {"n": name, "gid": group_id, "f": fail_threshold, "r": recover_threshold, "ss": silence_start, "se": silence_end, "em": escalation_minutes})
    return RedirectResponse("/admin", status_code=302)
