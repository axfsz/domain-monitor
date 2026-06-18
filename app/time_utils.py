from datetime import datetime
from zoneinfo import ZoneInfo

from config import TZ


def now_local() -> datetime:
    try:
        return datetime.now(ZoneInfo(TZ))
    except Exception:
        return datetime.now(ZoneInfo("Asia/Shanghai"))


def now_local_naive() -> datetime:
    return now_local().replace(tzinfo=None)


def format_local(fmt: str = "%Y-%m-%d %H:%M:%S") -> str:
    return now_local().strftime(fmt)


def timezone_label() -> str:
    try:
        ZoneInfo(TZ)
        zone_name = TZ
    except Exception:
        zone_name = "Asia/Shanghai"
    return "北京时间" if zone_name == "Asia/Shanghai" else zone_name


def format_local_with_label(fmt: str = "%Y-%m-%d %H:%M:%S") -> str:
    return f"{format_local(fmt)} {timezone_label()}"
