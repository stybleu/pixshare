from datetime import datetime, timezone


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def parse_dt(value: str) -> datetime:
    if not value:
        return datetime.min.replace(tzinfo=timezone.utc)
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except Exception:
        return datetime.min.replace(tzinfo=timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def get_remaining_time_label(expires_at: str | None) -> str:
    if not expires_at:
        return "Permanent"

    expiration = parse_dt(expires_at)

    if expiration == datetime.min.replace(tzinfo=timezone.utc):
        return "Permanent"

    now = utcnow()
    remaining = expiration - now

    if remaining.total_seconds() <= 0:
        return "Expiré"

    seconds = int(remaining.total_seconds())

    days = seconds // 86400
    hours = (seconds % 86400) // 3600
    minutes = (seconds % 3600) // 60

    if days > 0:
        return f"{days}j {hours}h"

    if hours > 0:
        return f"{hours}h {minutes}min"

    if minutes > 0:
        return f"{minutes}min"

    return "Moins d'1 min"