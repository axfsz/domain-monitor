import socket
import ssl
import time
import subprocess
from datetime import datetime, timezone
from urllib.parse import urlparse
import dns.resolver
import httpx
import whois
from config import HTTP_TIMEOUT, PING_ENABLED

def resolve_domain(domain: str) -> list[str]:
    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 5
    answers = resolver.resolve(domain, "A")
    return [item.to_text() for item in answers]

def check_port(host: str, port: int, timeout: int = 5) -> int:
    start = time.time()
    with socket.create_connection((host, port), timeout=timeout):
        return int((time.time() - start) * 1000)

def check_ssl(domain: str, port: int = 443):
    context = ssl.create_default_context()
    with socket.create_connection((domain, port), timeout=10) as sock:
        with context.wrap_socket(sock, server_hostname=domain) as ssock:
            cert = ssock.getpeercert()
    expire_str = cert.get("notAfter")
    expire_time = datetime.strptime(expire_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    days_left = (expire_time - datetime.now(timezone.utc)).days
    return expire_time.strftime("%Y-%m-%d %H:%M:%S UTC"), days_left

async def check_http(url: str, keyword: str = ""):
    start = time.time()
    async with httpx.AsyncClient(timeout=HTTP_TIMEOUT, follow_redirects=True, verify=True) as client:
        response = await client.get(url)
    elapsed = int((time.time() - start) * 1000)
    keyword_ok = True
    if keyword:
        try:
            keyword_ok = keyword in response.text
        except Exception:
            keyword_ok = False
    return response.status_code, elapsed, keyword_ok

def check_whois_expire(domain: str):
    try:
        data = whois.whois(domain)
        expire_date = data.expiration_date
        if isinstance(expire_date, list):
            expire_date = expire_date[0]
        if not expire_date:
            return None, None, "未获取到 WHOIS 到期时间"
        if expire_date.tzinfo is None:
            expire_date = expire_date.replace(tzinfo=timezone.utc)
        days_left = (expire_date - datetime.now(timezone.utc)).days
        return expire_date.strftime("%Y-%m-%d %H:%M:%S UTC"), days_left, None
    except Exception as e:
        return None, None, str(e)

def ping_domain(domain: str, timeout: int = 3):
    if not PING_ENABLED:
        return None, "PING_DISABLED"
    try:
        result = subprocess.run(["ping", "-c", "1", "-W", str(timeout), domain], capture_output=True, text=True, timeout=timeout + 2)
        return result.returncode == 0, result.stderr or result.stdout
    except Exception as e:
        return False, str(e)

def parse_url_paths(text_value: str):
    raw = (text_value or "/").replace(",", "\n")
    paths = []
    for line in raw.splitlines():
        item = line.strip()
        if not item or item.startswith("#"):
            continue
        if "://" in item:
            parsed = urlparse(item)
            path = parsed.path or "/"
            if parsed.query:
                path += "?" + parsed.query
            item = path
        if not item.startswith("/"):
            item = "/" + item
        if item not in paths:
            paths.append(item)
    return paths or ["/"]

def parse_expected_statuses(value: str):
    nums = set()
    for part in (value or "200,301,302").replace(";", ",").split(","):
        part = part.strip()
        if part.isdigit():
            nums.add(int(part))
    return nums or {200, 301, 302}
