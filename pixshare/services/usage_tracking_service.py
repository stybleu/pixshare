from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from urllib.parse import urlparse

from flask import request, url_for

from pixshare.services.json_services import load_usage, save_usage
from pixshare.services.request_service import get_client_ip

MAX_EVENTS_PER_FILE = 80
MAX_UA_LENGTH = 220
MAX_REFERER_LENGTH = 300

KNOWN_USER_AGENTS = {
    "telegrambot": ("Telegram", "preview_bot"),
    "discordbot": ("Discord", "preview_bot"),
    "facebookexternalhit": ("Facebook", "preview_bot"),
    "facebot": ("Facebook", "preview_bot"),
    "twitterbot": ("X / Twitter", "preview_bot"),
    "slackbot": ("Slack", "preview_bot"),
    "whatsapp": ("WhatsApp", "preview_bot"),
    "linkedinbot": ("LinkedIn", "preview_bot"),
    "pinterestbot": ("Pinterest", "preview_bot"),
    "redditbot": ("Reddit", "preview_bot"),
    "googlebot-image": ("Google Images", "search_bot"),
    "googlebot": ("Google", "search_bot"),
    "bingbot": ("Bing", "search_bot"),
    "yandexbot": ("Yandex", "search_bot"),
    "bytespider": ("ByteDance", "crawler"),
    "gptbot": ("GPTBot", "ai_crawler"),
    "claudebot": ("ClaudeBot", "ai_crawler"),
    "perplexitybot": ("PerplexityBot", "ai_crawler"),
}

KNOWN_REFERER_DOMAINS = {
    "reddit.com": "Reddit",
    "old.reddit.com": "Reddit",
    "www.reddit.com": "Reddit",
    "redd.it": "Reddit",
    "t.me": "Telegram",
    "telegram.org": "Telegram",
    "discord.com": "Discord",
    "discord.gg": "Discord",
    "facebook.com": "Facebook",
    "m.facebook.com": "Facebook",
    "x.com": "X / Twitter",
    "twitter.com": "X / Twitter",
    "whatsapp.com": "WhatsApp",
    "web.whatsapp.com": "WhatsApp",
    "pinterest.com": "Pinterest",
    "linkedin.com": "LinkedIn",
    "slack.com": "Slack",
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _clip(value: str, max_len: int) -> str:
    value = (value or "").strip()
    return value[:max_len]


def _domain_from_url(value: str) -> str:
    value = (value or "").strip()
    if not value:
        return ""
    try:
        parsed = urlparse(value)
        host = (parsed.netloc or "").lower()
        if "@" in host:
            host = host.rsplit("@", 1)[-1]
        if ":" in host:
            host = host.split(":", 1)[0]
        return host.replace("www.", "", 1)
    except Exception:
        return ""


def _same_site(domain: str) -> bool:
    if not domain:
        return False
    try:
        own = _domain_from_url(url_for("public.index", _external=True))
    except Exception:
        own = ""
    return bool(own and (domain == own or domain.endswith("." + own)))


def detect_source(referer: str, user_agent: str) -> dict:
    referer_domain = _domain_from_url(referer)
    ua_lower = (user_agent or "").lower()

    for needle, (name, category) in KNOWN_USER_AGENTS.items():
        if needle in ua_lower:
            return {
                "name": name,
                "category": category,
                "referer_domain": referer_domain,
                "is_external": False if _same_site(referer_domain) else bool(referer_domain),
                "confidence": "haute",
            }

    if referer_domain:
        for domain, name in KNOWN_REFERER_DOMAINS.items():
            clean_domain = domain.replace("www.", "", 1)
            if referer_domain == clean_domain or referer_domain.endswith("." + clean_domain):
                return {
                    "name": name,
                    "category": "platform",
                    "referer_domain": referer_domain,
                    "is_external": not _same_site(referer_domain),
                    "confidence": "moyenne",
                }

        if _same_site(referer_domain):
            if "/admin" in (referer or ""):
                name = "PixShare admin"
                category = "internal_admin"
            else:
                name = "PixShare"
                category = "internal"
            return {
                "name": name,
                "category": category,
                "referer_domain": referer_domain,
                "is_external": False,
                "confidence": "haute",
            }

        return {
            "name": referer_domain,
            "category": "external_site",
            "referer_domain": referer_domain,
            "is_external": True,
            "confidence": "moyenne",
        }

    if "bot" in ua_lower or "crawler" in ua_lower or "spider" in ua_lower:
        return {
            "name": "Bot inconnu",
            "category": "unknown_bot",
            "referer_domain": "",
            "is_external": False,
            "confidence": "faible",
        }

    return {
        "name": "Direct / inconnue",
        "category": "direct_unknown",
        "referer_domain": "",
        "is_external": False,
        "confidence": "faible",
    }


def record_usage_event(file_id: str, access_type: str, *, stored_filename: str = "") -> None:
    if not file_id:
        return

    referer = _clip(request.headers.get("Referer", ""), MAX_REFERER_LENGTH)
    user_agent = _clip(request.headers.get("User-Agent", ""), MAX_UA_LENGTH)
    source = detect_source(referer, user_agent)

    data = load_usage()
    record = data.get(file_id)
    if not isinstance(record, dict):
        record = {"events": []}

    events = record.get("events")
    if not isinstance(events, list):
        events = []

    event = {
        "at": _now_iso(),
        "access_type": access_type,
        "ip": get_client_ip(),
        "referer": referer,
        "referer_domain": source.get("referer_domain", ""),
        "user_agent": user_agent,
        "source_name": source.get("name", "Direct / inconnue"),
        "source_category": source.get("category", "direct_unknown"),
        "is_external": bool(source.get("is_external", False)),
        "confidence": source.get("confidence", "faible"),
        "stored_filename": stored_filename,
    }

    events.append(event)
    events = events[-MAX_EVENTS_PER_FILE:]
    record["events"] = events
    data[file_id] = record
    save_usage(data)


def build_usage_summary(file_id: str) -> dict:
    data = load_usage()
    record = data.get(file_id) if isinstance(data, dict) else {}
    events = record.get("events", []) if isinstance(record, dict) else []
    if not isinstance(events, list):
        events = []

    by_access = Counter()
    by_source = Counter()
    by_category = Counter()
    external_sources = Counter()
    bot_hits = 0
    suspicious_hits = 0

    for ev in events:
        if not isinstance(ev, dict):
            continue
        access = ev.get("access_type") or "unknown"
        source_name = ev.get("source_name") or "Direct / inconnue"
        category = ev.get("source_category") or "unknown"
        by_access[access] += 1
        by_source[source_name] += 1
        by_category[category] += 1
        if ev.get("is_external"):
            external_sources[source_name] += 1
        if category in {"preview_bot", "search_bot", "crawler", "ai_crawler", "unknown_bot"}:
            bot_hits += 1
        if category in {"external_site", "unknown_bot", "crawler", "ai_crawler"}:
            suspicious_hits += 1

    last_events = list(reversed(events[-8:]))

    return {
        "total": len(events),
        "viewer": by_access.get("viewer", 0),
        "raw": by_access.get("raw", 0),
        "download": by_access.get("download", 0),
        "api_raw": by_access.get("api_raw", 0),
        "image_page": by_access.get("image_page", 0),
        "bot_hits": bot_hits,
        "external_hits": sum(external_sources.values()),
        "suspicious_hits": suspicious_hits,
        "sources": [{"name": name, "count": count} for name, count in by_source.most_common(8)],
        "external_sources": [{"name": name, "count": count} for name, count in external_sources.most_common(8)],
        "categories": [{"name": name, "count": count} for name, count in by_category.most_common(8)],
        "last_events": last_events,
    }
