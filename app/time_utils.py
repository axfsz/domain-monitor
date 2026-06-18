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


def format_local_with_label(fmt: str = "%Y-%m-%d %H:%M:%S") -> str:
    return f"{format_local(fmt)} 北京时间"
