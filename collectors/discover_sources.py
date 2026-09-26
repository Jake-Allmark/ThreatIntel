import re
from urllib.parse import urljoin

import feedparser
import httpx
from bs4 import BeautifulSoup


HEADERS = {
    "User-Agent": (
        "ThreatIntel/0.1 "
        "(defensive cybersecurity research)"
    ),
    "Accept": (
        "text/html,application/xhtml+xml,"
        "application/rss+xml,"
        "application/atom+xml,"
        "application/xml,*/*"
    ),
}


SOURCES = [
    {
        "name": "CISA Cybersecurity Advisories",
        "site": "https://www.cisa.gov/news-events/cybersecurity-advisories",
    },
    {
        "name": "Dark Reading",
        "site": "https://www.darkreading.com/",
    },
    {
        "name": "Google Threat Intelligence / Mandiant",
        "site": "https://cloud.google.com/blog/topics/threat-intelligence",
    },
    {
        "name": "MSRC",
        "site": "https://msrc.microsoft.com/blog/",
    },
    {
        "name": "CrowdStrike",
        "site": "https://www.crowdstrike.com/en-us/blog/",
    },
    {
        "name": "Sophos X-Ops",
        "site": "https://news.sophos.com/en-us/category/threat-research/",
    },
    {
        "name": "Trend Micro Research",
        "site": "https://www.trendmicro.com/en_us/research.html",
    },
    {
        "name": "Check Point Research",
        "site": "https://research.checkpoint.com/",
    },
    {
        "name": "Fortinet FortiGuard Labs",
        "site": "https://www.fortinet.com/blog/threat-research",
    },
    {
        "name": "Proofpoint Threat Insight",
        "site": "https://www.proofpoint.com/us/blog/threat-insight",
    },
    {
        "name": "Elastic Security Labs",
        "site": "https://www.elastic.co/security-labs",
    },
    {
        "name": "SANS Internet Storm Center",
        "site": "https://isc.sans.edu/",
    },
    {
        "name": "The DFIR Report",
        "site": "https://thedfirreport.com/",
    },
]


COMMON_PATHS = [
    "feed/",
    "feed",
    "rss/",
    "rss",
    "rss.xml",
    "feed.xml",
    "atom.xml",
    "index.xml",
]


def unique(values):
    result = []
    seen = set()

    for value in values:
        if not value:
            continue

        value = value.strip()

        if value in seen:
            continue

        seen.add(value)
        result.append(value)

    return result


def looks_like_feed(content):
    parsed = feedparser.parse(content)

    return len(parsed.entries) > 0


def test_feed(url):
    try:
        response = httpx.get(
            url,
            headers=HEADERS,
            timeout=15.0,
            follow_redirects=True,
        )

        response.raise_for_status()

        parsed = feedparser.parse(
            response.content
        )

        if not parsed.entries:
            return None

        latest = parsed.entries[0].get(
            "title",
            "Untitled",
        )

        return {
            "url": str(response.url),
            "entries": len(parsed.entries),
            "latest": re.sub(
                r"\s+",
                " ",
                latest,
            ).strip(),
        }

    except Exception:
        return None


def discover_html_feeds(site):
    candidates = []

    try:
        response = httpx.get(
            site,
            headers=HEADERS,
            timeout=20.0,
            follow_redirects=True,
        )

        response.raise_for_status()

        soup = BeautifulSoup(
            response.text,
            "html.parser",
        )

        for link in soup.find_all(
            "link",
            href=True,
        ):
            link_type = (
                link.get("type", "")
                .lower()
            )

            rel = " ".join(
                link.get("rel", [])
            ).lower()

            if (
                "rss" in link_type
                or "atom" in link_type
                or "alternate" in rel
            ):
                href = urljoin(
                    str(response.url),
                    link["href"],
                )

                candidates.append(
                    href
                )

        return candidates

    except Exception:
        return []


def discover_common_paths(site):
    base = site.rstrip("/") + "/"

    candidates = []

    for path in COMMON_PATHS:
        candidates.append(
            urljoin(
                base,
                path,
            )
        )

    return candidates


def discover_source(source):
    site = source["site"]

    candidates = []

    candidates.extend(
        discover_html_feeds(
            site
        )
    )

    candidates.extend(
        discover_common_paths(
            site
        )
    )

    #
    # Also try common feed paths from the
    # website's root rather than only the
    # supplied article/category page.
    #
    try:
        from urllib.parse import urlparse

        parsed = urlparse(site)

        root = (
            f"{parsed.scheme}://"
            f"{parsed.netloc}/"
        )

        candidates.extend(
            discover_common_paths(
                root
            )
        )

    except Exception:
        pass

    candidates = unique(
        candidates
    )

    for candidate in candidates:
        result = test_feed(
            candidate
        )

        if result:
            return result

    return None


def main():
    print()
    print(
        "ThreatIntel Source Discovery"
    )
    print(
        "=" * 70
    )

    working = []
    unresolved = []

    for source in SOURCES:
        print()
        print(
            "Searching:",
            source["name"],
        )

        result = discover_source(
            source
        )

        if result:
            working.append(
                {
                    "name": source["name"],
                    **result,
                }
            )

            print(
                "  PASS"
            )

            print(
                "  Feed:",
                result["url"],
            )

            print(
                "  Entries:",
                result["entries"],
            )

            print(
                "  Latest:",
                result["latest"],
            )

        else:
            unresolved.append(
                source
            )

            print(
                "  NO FEED DISCOVERED"
            )

    print()
    print(
        "=" * 70
    )

    print(
        "SUMMARY"
    )

    print(
        "Working:",
        len(working),
    )

    print(
        "Unresolved:",
        len(unresolved),
    )

    if working:
        print()
        print(
            "VERIFIED WORKING FEEDS"
        )

        for source in working:
            print()
            print(
                source["name"]
            )

            print(
                source["url"]
            )

    if unresolved:
        print()
        print(
            "NEED SPECIAL COLLECTOR / FURTHER CHECK"
        )

        for source in unresolved:
            print(
                "-",
                source["name"],
            )

    print()
    print(
        "Discovery complete."
    )


if __name__ == "__main__":
    main()