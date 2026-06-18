from datetime import datetime
import httpx
from config import WECHAT_WEBHOOK_URL, TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID, NOTIFY_CHANNEL, DAILY_REPORT_CHANNEL

def build_wechat_markdown(result: dict, recovered: bool = False) -> str:
    if recovered:
        title = "✅ 域名恢复通知"
        color = "info"
    elif result.get("alert_level") == "critical":
        title = "🔥 域名严重告警"
        color = "warning"
    else:
        title = "🚨 域名异常告警"
        color = "warning"
    return f"""
# {title}

> 域名：<font color=\"{color}\">{result.get('domain','-')}</font>
> 分组：{result.get('group_name','default')}
> 标签：{result.get('tags','-')}
> 状态：<font color=\"{color}\">{result.get('status','-')}</font>
> 探测节点：{result.get('agent_name','local')} / {result.get('agent_region','-')}

**HTTP 检测**
> 状态码：{result.get('http_code','-')}
> 响应时间：{result.get('response_time_ms','-')} ms
> URL 检测：{result.get('urls_checked','-')} 个

**DNS 检测**
> 解析 IP：{result.get('resolved_ips','-')}

**证书与域名注册**
> SSL 剩余：{result.get('ssl_days_left','-')} 天
> SSL 到期：{result.get('ssl_expire_at','-')}
> Whois 剩余：{result.get('whois_days_left','-')} 天
> Whois 到期：{result.get('whois_expire_at','-')}

**Ping 检测**
> Ping：{result.get('ping_ok','-')}

**异常信息**
> <font color=\"{color}\">{result.get('error') or '-'}</font>

---
时间：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
系统：Domain Monitor
""".strip()

def build_plain_text(result: dict, recovered: bool = False) -> str:
    title = "✅ 域名恢复通知" if recovered else ("🔥 域名严重告警" if result.get("alert_level") == "critical" else "🚨 域名异常告警")
    return f"""{title}
━━━━━━━━━━━━━━━━━━
🌐 域名: {result.get('domain','-')}
📁 分组: {result.get('group_name','default')}
🏷 标签: {result.get('tags','-')}
📌 状态: {result.get('status','-')}
🛰 节点: {result.get('agent_name','local')} / {result.get('agent_region','-')}

HTTP: {result.get('http_code','-')}
响应: {result.get('response_time_ms','-')} ms
URL检测: {result.get('urls_checked','-')} 个
解析IP: {result.get('resolved_ips','-')}
SSL剩余: {result.get('ssl_days_left','-')} 天
Whois剩余: {result.get('whois_days_left','-')} 天
Ping: {result.get('ping_ok','-')}

错误: {result.get('error') or '-'}
时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
""".strip()

def build_daily_report_text(summary: dict) -> str:
    lines = [
        "📊 Domain Monitor 每日巡检报告",
        "━━━━━━━━━━━━━━━━━━",
        f"日期: {summary.get('date')}",
        f"总数: {summary.get('total')} | 正常: {summary.get('ok')} | 警告: {summary.get('warning')} | 异常: {summary.get('error')}",
        f"SSL 15天内到期: {summary.get('ssl_soon')}",
        f"Whois 30天内到期: {summary.get('whois_soon')}",
        "",
        "异常/警告明细:",
    ]
    bad = summary.get('bad', [])
    if not bad:
        lines.append("✅ 暂无异常")
    else:
        for item in bad[:30]:
            lines.append(f"- {item.get('domain')} [{item.get('group_name')}] {item.get('status')} | {item.get('error') or '-'}")
        if len(bad) > 30:
            lines.append(f"... 其余 {len(bad)-30} 条已省略")
    lines.extend(["", f"系统时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"])
    return "\n".join(lines)

async def _send_telegram_text(text: str):
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        print("telegram skipped: TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID is empty", flush=True)
        return
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {"chat_id": TELEGRAM_CHAT_ID, "text": text, "disable_web_page_preview": True}
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.post(url, json=payload)
        if resp.status_code >= 300:
            print(f"telegram error: {resp.status_code} {resp.text}", flush=True)

async def _send_wechat_markdown(text: str):
    if not WECHAT_WEBHOOK_URL:
        print("wechat skipped: WECHAT_WEBHOOK_URL is empty", flush=True)
        return
    payload = {"msgtype": "markdown", "markdown": {"content": text}}
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.post(WECHAT_WEBHOOK_URL, json=payload)
        if resp.status_code >= 300:
            print(f"wechat error: {resp.status_code} {resp.text}", flush=True)

async def send_wechat(result: dict, recovered: bool = False):
    await _send_wechat_markdown(build_wechat_markdown(result, recovered))

async def send_telegram(result: dict, recovered: bool = False):
    await _send_telegram_text(build_plain_text(result, recovered))

async def send_notice(result: dict, recovered: bool = False):
    if NOTIFY_CHANNEL in ("wechat", "both"):
        await send_wechat(result, recovered)
    if NOTIFY_CHANNEL in ("telegram", "both"):
        await send_telegram(result, recovered)

async def send_daily_report(summary: dict):
    text = build_daily_report_text(summary)
    channel = DAILY_REPORT_CHANNEL or NOTIFY_CHANNEL
    if channel in ("telegram", "both"):
        await _send_telegram_text(text)
    if channel in ("wechat", "both"):
        await _send_wechat_markdown(text)
