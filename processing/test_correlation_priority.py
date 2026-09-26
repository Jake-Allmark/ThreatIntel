from processing.correlate import correlate_records
from processing.score import calculate_priority


def empty_iocs():
    return {
        "ipv4": [],
        "domains": [],
        "urls": [],
        "md5": [],
        "sha1": [],
        "sha256": [],
    }


#
# Source A knows this is a critical-severity
# vulnerability and that it is in CISA KEV,
# but does NOT report current exploitation.
#
report_a = {
    "source": "Source A",
    "title": "Vendor fixes CVE-2026-12345",
    "url": "https://source-a.example/report",
    "published_at": None,
    "summary": "Vendor security advisory.",
    "evidence_text": (
        "The vendor released an update for "
        "CVE-2026-12345."
    ),
    "cves": [
        "CVE-2026-12345",
    ],
    "iocs": empty_iocs(),
    "nvd": [
        {
            "cve": "CVE-2026-12345",
            "cvss": {
                "score": 9.8,
            },
        },
    ],
    "kev": [
        {
            "cve": "CVE-2026-12345",
            "ransomware_use": "Unknown",
        },
    ],
}


#
# Calculate Source A's original priority.
#
report_a["priority"] = calculate_priority(
    report_a
)


assert (
    report_a["priority"]["level"]
    == "HIGH"
), (
    "Source A should initially be HIGH"
)


assert (
    report_a["priority"]["score"]
    == 35
), (
    "Source A should initially score 35"
)


#
# Source B reports the same event and explicitly
# supplies current exploitation evidence.
#
report_b = {
    "source": "Source B",
    "title": "Vendor fixes CVE-2026-12345",
    "url": "https://source-b.example/report",
    "published_at": None,
    "summary": (
        "Researchers observed exploitation."
    ),
    "evidence_text": (
        "Researchers report CVE-2026-12345 "
        "is actively exploited in attacks."
    ),
    "cves": [
        "CVE-2026-12345",
    ],
    "iocs": empty_iocs(),
    "nvd": [
        {
            "cve": "CVE-2026-12345",
            "cvss": {
                "score": 9.8,
            },
        },
    ],
    "kev": [
        {
            "cve": "CVE-2026-12345",
            "ransomware_use": "Unknown",
        },
    ],
}


report_b["priority"] = calculate_priority(
    report_b
)


#
# Correlate the two reports.
#
events = correlate_records(
    [
        report_a,
        report_b,
    ]
)


assert len(events) == 1, (
    f"Expected one correlated event, "
    f"got {len(events)}"
)


event = events[0]


#
# Combined evidence should now include the
# active-exploitation statement from Source B.
#
assert (
    "actively exploited"
    in event["evidence_text"].lower()
), (
    "Merged evidence is missing "
    "Source B exploitation evidence"
)


#
# Most importantly, priority must have been
# recalculated AFTER the merge.
#
assert (
    event["priority"]["level"]
    == "CRITICAL"
), (
    "Merged event should become CRITICAL, "
    f"got {event['priority']['level']}"
)


assert (
    event["priority"]["score"]
    == 65
), (
    "Merged event should score 65, "
    f"got {event['priority']['score']}"
)


assert (
    event["priority"][
        "active_exploitation_language"
    ]
    is True
)


print(
    "PASS - initial Source A priority:",
    report_a["priority"]["level"],
    report_a["priority"]["score"],
)

print(
    "PASS - merged event priority:",
    event["priority"]["level"],
    event["priority"]["score"],
)

print(
    "PASS - sources:",
    event["correlation"]["source_count"],
)

print(
    "PASS - combined exploitation evidence detected"
)

print(
    "\nAll correlated priority tests passed."
)