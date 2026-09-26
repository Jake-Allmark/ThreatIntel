import json

from ai.client import analyse_event

event = {
    "title": "Test Example Vulnerability",
    "sources": [
        {
            "source": "Test Security Source",
            "title": "Test Example Vulnerability",
            "url": "https://example.invalid/report",
            "published_at": "2026-09-23T10:00:00+00:00",
        }
    ],
    "evidence_reports": [
        {
            "source": "Test Security Source",
            "title": "Test Example Vulnerability",
            "url": "https://example.invalid/report",
            "published_at": "2026-09-23T10:00:00+00:00",
            "evidence_text": (
                "ExampleCorp reports that CVE-2026-12345 "
                "affects ExampleGateway. The vulnerability "
                "has been observed being exploited in attacks. "
                "ExampleCorp recommends installing the vendor "
                "security update. The report does not identify "
                "the affected software versions, threat actor, "
                "malware family, or victim organizations."
            ),
            "cves": [
                "CVE-2026-12345"
            ],
            "iocs": {
                "ipv4": [],
                "domains": [],
                "urls": [],
                "md5": [],
                "sha1": [],
                "sha256": [],
            },
        }
    ],
    "cves": [
        "CVE-2026-12345"
    ],
    "nvd": [],
    "kev": [],
    "iocs": {
        "ipv4": [],
        "domains": [],
        "urls": [],
        "md5": [],
        "sha1": [],
        "sha256": [],
    },
    "correlation": {
        "source_count": 1,
        "evidence_report_count": 1,
        "matches": [],
    },
}


result = analyse_event(event)

print(
    json.dumps(
        result,
        indent=2,
        default=str,
    )
)