import feedparser
import httpx


HEADERS = {
    "User-Agent": (
        "ThreatIntel/0.1 "
        "(defensive cybersecurity research)"
    ),
    "Accept": (
        "application/rss+xml, "
        "application/atom+xml, "
        "application/xml, "
        "text/xml, */*"
    ),
}


CANDIDATE_FEEDS = [
    {
        "name": "KrebsOnSecurity",
        "url": "https://krebsonsecurity.com/feed/",
    },
    {
        "name": "The Record",
        "url": "https://therecord.media/feed/",
    },
    {
        "name": "CyberScoop",
        "url": "https://cyberscoop.com/feed/",
    },
    {
        "name": "Cisco Talos Intelligence",
        "url": "https://blog.talosintelligence.com/rss/",
    },
    {
        "name": "Palo Alto Unit 42",
        "url": "https://unit42.paloaltonetworks.com/feed/",
    },
    {
        "name": "Google Project Zero",
        "url": (
            "https://googleprojectzero.blogspot.com/"
            "feeds/posts/default?alt=rss"
        ),
    },
    {
        "name": "Microsoft Security Blog",
        "url": (
            "https://www.microsoft.com/"
            "en-us/security/blog/feed/"
        ),
    },
    {
        "name": "SentinelLabs",
        "url": (
            "https://www.sentinelone.com/"
            "labs/feed/"
        ),
    },
    {
        "name": "ESET WeLiveSecurity",
        "url": (
            "https://www.welivesecurity.com/"
            "en/rss/feed/"
        ),
    },
    {
        "name": "Rapid7 Research",
        "url": "https://blog.rapid7.com/rss/",
    },
]


def validate_feed(source):
    name = source["name"]
    url = source["url"]

    try:
        response = httpx.get(
            url,
            headers=HEADERS,
            timeout=20.0,
            follow_redirects=True,
        )

        response.raise_for_status()

        parsed = feedparser.parse(
            response.content
        )

        entries = len(
            parsed.entries
        )

        if entries == 0:
            return {
                "name": name,
                "url": url,
                "status": "FAILED",
                "entries": 0,
                "error": (
                    "Feed returned no entries"
                ),
            }

        first = parsed.entries[0]

        return {
            "name": name,
            "url": url,
            "status": "PASS",
            "entries": entries,
            "latest": first.get(
                "title",
                "Untitled",
            ),
            "error": None,
        }

    except Exception as error:
        return {
            "name": name,
            "url": url,
            "status": "FAILED",
            "entries": 0,
            "error": str(error),
        }


def main():
    print()
    print(
        "ThreatIntel Candidate Feed Validator"
    )
    print(
        "=" * 60
    )

    passed = []
    failed = []

    for source in CANDIDATE_FEEDS:
        print(
            f"\nTesting: {source['name']}"
        )

        result = validate_feed(
            source
        )

        if result["status"] == "PASS":
            passed.append(
                result
            )

            print(
                "  PASS"
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
            failed.append(
                result
            )

            print(
                "  FAILED"
            )

            print(
                "  Error:",
                result["error"],
            )

    print()
    print(
        "=" * 60
    )

    print(
        "RESULT"
    )

    print(
        "Passed:",
        len(passed),
    )

    print(
        "Failed:",
        len(failed),
    )

    if passed:
        print()
        print(
            "WORKING FEEDS"
        )

        for result in passed:
            print(
                f"  + {result['name']}"
            )

    if failed:
        print()
        print(
            "FAILED FEEDS"
        )

        for result in failed:
            print(
                f"  - {result['name']}"
            )

    print()
    print(
        "Validation complete."
    )


if __name__ == "__main__":
    main()