from config import WARNING_FAIL_THRESHOLD, ERROR_FAIL_THRESHOLD

def effective_status(status: str | None, fail_count: int | None) -> str:
    normalized = (status or "ok").strip().lower()
    count = int(fail_count or 0)
    if normalized == "error":
        return "error" if count >= max(1, ERROR_FAIL_THRESHOLD) else "ok"
    if normalized == "warning":
        return "warning" if count >= max(1, WARNING_FAIL_THRESHOLD) else "ok"
    return "ok"
