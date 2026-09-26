from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime

import feedparser
import httpx


HEADERS = {
    "User-Agent": (
        "ThreatIntel/0.1 "
        "(defensive cybersecurity research)"
    ),
    "Accept": (
        "application/rss+xml, application/atom+xml, "
        "application/xml, text/xml, */*"
    ),
}


def parse_date(entry):
    """
    Determine when an RSS/Atom item was published.

    Returns a timezone-aware UTC datetime,
    or None if no reliable date is available.
    """

    for field in ("published", "updated", "created"):
        value = entry.get(field)

        if not value:
            continue

        try:
            parsed = parsedate_to_datetime(value)

            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)

            return parsed.astimezone(timezone.utc)

        except (TypeError, ValueError, OverflowError):
            pass

    for field in ("published_parsed", "updated_parsed"):
        value = entry.get(field)

        if value:
            try:
                return datetime(
                    *value[:6],
                    tzinfo=timezone.utc,
                )
            except (TypeError, ValueError):
                pass

    return None


def download_feed(url):
    """
    Download a feed with explicit timeout, redirects,
    headers and HTTP error handling.
    """

    response = httpx.get(
        url,
        headers=HEADERS,
        timeout=20.0,
        follow_redirects=True,
    )

    response.raise_for_status()

    return response.content


def collect_feed(source_name, url, hours=24):
    """
    Download and normalize recent RSS/Atom entries.
    """

    content = download_feed(url)

    feed = feedparser.parse(content)

    if getattr(feed, "bozo", False) and not feed.entries:
        error = getattr(
            feed,
            "bozo_exception",
            "Unknown parsing error",
        )

        raise RuntimeError(
            f"{source_name} feed parsing failed: {error}"
        )

    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)

    results = []

    for entry in feed.entries:
        published = parse_date(entry)

        # Don't classify an undated article as recent.
        if published is None:
            continue

        if published < cutoff:
            continue

        title = entry.get(
            "title",
            "Untitled report",
        )

        results.append(
            {
                "source": source_name,
                "title": title.strip(),
                "url": entry.get("link", ""),
                "published_at": published,
                "summary": entry.get("summary", ""),
                "raw_entry": entry,
            }
        )

    # Newest intelligence first.
    results.sort(
        key=lambda item: item["published_at"],
        reverse=True,
    )

    return results