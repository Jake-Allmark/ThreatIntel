import sys

import feedparser
import httpx

from collectors.feeds import (
    collect_feed,
    parse_date,
)


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


def test_source(name, url):
    print()
    print("=" * 60)
    print("THREATINTEL SOURCE VALIDATOR")
    print("=" * 60)

    print(f"Source: {name}")
    print(f"URL:    {url}")
    print()

    # -----------------------------------------
    # 1. HTTP retrieval
    # -----------------------------------------

    print("[1/5] Testing HTTP retrieval...")

    response = httpx.get(
        url,
        headers=HEADERS,
        timeout=30.0,
        follow_redirects=True,
    )

    response.raise_for_status()

    print(
        f"      OK - HTTP {response.status_code}"
    )

    print(
        "      Content-Type:",
        response.headers.get(
            "content-type",
            "Unknown",
        ),
    )

    # -----------------------------------------
    # 2. Feed parsing
    # -----------------------------------------

    print()
    print("[2/5] Testing RSS/Atom parsing...")

    feed = feedparser.parse(
        response.content
    )

    if feed.bozo and not feed.entries:
        raise RuntimeError(
            f"Feed parsing failed: "
            f"{feed.bozo_exception}"
        )

    print(
        f"      OK - {len(feed.entries)} "
        "feed entries discovered"
    )

    # -----------------------------------------
    # 3. Date parsing
    # -----------------------------------------

    print()
    print("[3/5] Testing publication dates...")

    dated_entries = 0

    for entry in feed.entries:
        if parse_date(entry):
            dated_entries += 1

    print(
        f"      {dated_entries}/"
        f"{len(feed.entries)} entries "
        "have usable dates"
    )

    if feed.entries and dated_entries == 0:
        raise RuntimeError(
            "Feed entries were found, but none "
            "had usable publication dates."
        )

    # -----------------------------------------
    # 4. Inspect sample articles
    # -----------------------------------------

    print()
    print("[4/5] Inspecting sample entries...")

    for entry in feed.entries[:3]:
        title = entry.get(
            "title",
            "Untitled",
        )

        link = entry.get(
            "link",
            "",
        )

        published = parse_date(
            entry
        )

        print()
        print(
            "      TITLE:",
            title,
        )

        print(
            "      DATE: ",
            published,
        )

        print(
            "      URL:  ",
            link,
        )

    # -----------------------------------------
    # 5. Test our real 24-hour collector
    # -----------------------------------------

    print()
    print(
        "[5/5] Testing ThreatIntel "
        "24-hour filtering..."
    )

    recent = collect_feed(
        name,
        url,
        hours=24,
    )

    print(
        f"      OK - {len(recent)} "
        "report(s) in last 24 hours"
    )

    print()
    print("=" * 60)
    print("SOURCE TEST PASSED")
    print("=" * 60)


def main():
    if len(sys.argv) != 3:
        print(
            'Usage: python test_source.py '
            '"Source Name" "Feed URL"'
        )

        return

    name = sys.argv[1]
    url = sys.argv[2]

    try:
        test_source(
            name,
            url,
        )

    except Exception as error:
        print()
        print("=" * 60)
        print("SOURCE TEST FAILED")
        print("=" * 60)
        print(
            f"{type(error).__name__}: "
            f"{error}"
        )


if __name__ == "__main__":
    main()