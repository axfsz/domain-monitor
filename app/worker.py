import asyncio
import time
from config import CHECK_INTERVAL_SECONDS, DAILY_REPORT_ENABLED, DAILY_REPORT_TIME
from database import init_db
from auth import ensure_admin_user
from monitor import check_all_domains, build_daily_summary
from notify import send_daily_report
from time_utils import now_local

def _should_send_daily(last_sent_date: str | None) -> bool:
    if not DAILY_REPORT_ENABLED:
        return False
    now = now_local()
    today = now.strftime("%Y-%m-%d")
    if last_sent_date == today:
        return False
    try:
        hour, minute = [int(x) for x in DAILY_REPORT_TIME.split(":", 1)]
    except Exception:
        hour, minute = 9, 0
    return (now.hour, now.minute) >= (hour, minute)

def main():
    init_db()
    ensure_admin_user()
    last_daily_date = None
    while True:
        try:
            results = asyncio.run(check_all_domains())
            print(f"checked domains: {len(results)}", flush=True)
            if _should_send_daily(last_daily_date):
                summary = build_daily_summary()
                asyncio.run(send_daily_report(summary))
                last_daily_date = now_local().strftime("%Y-%m-%d")
                print("daily report sent", flush=True)
        except Exception as e:
            print(f"worker error: {e}", flush=True)
        time.sleep(CHECK_INTERVAL_SECONDS)

if __name__ == "__main__":
    main()
