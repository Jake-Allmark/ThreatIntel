import json
from datetime import (
    datetime,
    timezone,
)

from reporting.json_report import (
    build_report,
    serialize_report,
)


events = [
    {
        "title": "Critical Event",
        "published_at": datetime(
            2026,
            9,
            23,
            10,
            30,
            tzinfo=timezone.utc,
        ),
        "cves": [
            "CVE-2026-11111",
        ],
        "kev": [
            {
                "cve": "CVE-2026-11111",
            },
        ],
        "iocs": {
            "ipv4": [
                "203.0.113.10",
            ],
            "domains": [
                "evil.example",
            ],
            "urls": [],
            "md5": [],
            "sha1": [],
            "sha256": [],
        },
        "priority": {
            "level": "CRITICAL",
            "score": 65,
        },
        "ai_status": "success",
    },
    {
        "title": "Medium Event",
        "published_at": datetime(
            2026,
            9,
            23,
            11,
            0,
            tzinfo=timezone.utc,
        ),
        "cves": [
            "CVE-2026-22222",
        ],
        "kev": [],
        "iocs": {
            "ipv4": [],
            "domains": [],
            "urls": [],
            "md5": [],
            "sha1": [],
            "sha256": [],
        },
        "priority": {
            "level": "MEDIUM",
            "score": 15,
        },
        "ai_status": "skipped_budget",
    },
]


ai_usage = {
    "input_tokens": 800,
    "output_tokens": 300,
    "total_tokens": 1100,
    "completed_calls": 1,
    "failed_calls": 0,
    "skipped_calls": 1,
    "token_limit": 1000,
    "limit_reached": True,
}


report = build_report(
    events,
    collection_hours=24,
    report_count=3,
    failures=[],
    ai_usage=ai_usage,
)


assert report["metadata"]["schema_version"] == "1.0"
assert report["metadata"]["reports_collected"] == 3
assert report["metadata"]["correlated_events"] == 2

assert report["summary"]["critical"] == 1
assert report["summary"]["medium"] == 1
assert report["summary"]["cves"] == 2
assert report["summary"]["kev"] == 1
assert report["summary"]["candidate_iocs"] == 2


# datetime must have become a JSON-safe
# ISO-8601 string.
assert isinstance(
    report["events"][0]["published_at"],
    str,
)


text = serialize_report(
    report
)

parsed = json.loads(
    text
)


assert (
    parsed["events"][0]["title"]
    == "Critical Event"
)

assert (
    parsed["metadata"]["ai_usage"]["total_tokens"]
    == 1100
)


print("PASS - canonical report built")
print("PASS - priority counts correct")
print("PASS - CVE/KEV counts correct")
print("PASS - IOC count correct")
print("PASS - datetime JSON conversion correct")
print("PASS - report serializes and parses")

print()
print("All JSON report tests passed.")