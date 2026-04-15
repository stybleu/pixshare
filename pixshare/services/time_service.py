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


def format_duration_minutes(total_minutes: int) -> str:
    try:
        total_minutes = int(total_minutes)
    except (TypeError, ValueError):
        return "Moins d'1 min"

    if total_minutes <= 0:
        return "Moins d'1 min"

    days = total_minutes // 1440
    hours = (total_minutes % 1440) // 60
    minutes = total_minutes % 60

    if days > 0:
        if hours > 0:
            return f"{days} j {hours} h"
        return f"{days} j"

    if hours > 0:
        if minutes > 0:
            return f"{hours} h {minutes} min"
        return f"{hours} h"

    return f"{minutes} min"


def get_remaining_time_label(expires_at: str | None) -> str:
    if not expires_at:
        return "Permanent"

    expiration = parse_dt(expires_at)

    if expiration == datetime.min.replace(tzinfo=timezone.utc):
        return "Permanent"

    now = utcnow()
    remaining = expiration - now

    total_seconds = int(remaining.total_seconds())

    if total_seconds <= 0:
        return "Expiré"

    total_minutes = total_seconds // 60

    if total_minutes <= 0:
        return "Moins d'1 min"

    return format_duration_minutes(total_minutes)