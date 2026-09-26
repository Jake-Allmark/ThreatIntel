from processing.correlate import correlate_records


report_a = {
    "source": "Source A",
    "title": "Vendor fixes CVE-2026-12345",
    "url": "https://source-a.example/report",
    "published_at": None,
    "summary": "First report.",
    "evidence_text": (
        "CVE-2026-12345 was reported. "
        "Indicator 192.0.2.10 was observed."
    ),
    "cves": [
        "CVE-2026-12345",
    ],
    "iocs": {
        "ipv4": [
            "192.0.2.10",
        ],
        "domains": [],
        "urls": [],
        "md5": [],
        "sha1": [],
        "sha256": [],
    },
    "nvd": [
        {
            "cve": "CVE-2026-12345",
            "description": "NVD record A",
        },
    ],
    "kev": [
        {
            "cve": "CVE-2026-12345",
            "product": "Example Product",
        },
    ],
}


report_b = {
    "source": "Source B",

    # Same event title so correlation is justified.
    # Source B still contributes extra evidence below.
    "title": "Vendor fixes CVE-2026-12345",

    "url": "https://source-b.example/report",
    "published_at": None,
    "summary": "Second report.",
    "evidence_text": (
        "CVE-2026-12345 and CVE-2026-67890 "
        "were discussed. "
        "Indicator malicious.example was observed."
    ),
    "cves": [
        "CVE-2026-12345",
        "CVE-2026-67890",
    ],
    "iocs": {
        "ipv4": [],
        "domains": [
            "malicious.example",
        ],
        "urls": [],
        "md5": [],
        "sha1": [],
        "sha256": [],
    },
    "nvd": [
        {
            "cve": "CVE-2026-12345",
            "description": "Duplicate NVD record",
        },
        {
            "cve": "CVE-2026-67890",
            "description": "NVD record B",
        },
    ],
    "kev": [
        {
            "cve": "CVE-2026-67890",
            "product": "Second Product",
        },
    ],
}


events = correlate_records(
    [
        report_a,
        report_b,
    ]
)


#
# The two reports should become one event.
#
assert len(events) == 1, (
    f"Expected 1 correlated event, "
    f"got {len(events)}"
)


event = events[0]


#
# Evidence from both reports must survive.
#
assert set(event["cves"]) == {
    "CVE-2026-12345",
    "CVE-2026-67890",
}


assert event["iocs"]["ipv4"] == [
    "192.0.2.10",
]


assert event["iocs"]["domains"] == [
    "malicious.example",
]


#
# Duplicate NVD record for CVE-2026-12345
# should not create a duplicate.
#
assert len(event["nvd"]) == 2, (
    "Expected two unique NVD records"
)


#
# Each CVE has one KEV record.
#
assert len(event["kev"]) == 2, (
    "Expected two unique KEV records"
)


#
# Provenance from both reports must remain.
#
assert len(event["sources"]) == 2, (
    "Expected both source records"
)


assert len(
    event["evidence_reports"]
) == 2, (
    "Expected both evidence reports"
)


assert (
    event["correlation"]["source_count"]
    == 2
)


assert (
    event["correlation"][
        "evidence_report_count"
    ]
    == 2
)


#
# Display the result.
#
print(
    "PASS - reports correlated"
)

print(
    "CVEs:",
    event["cves"],
)

print(
    "IPv4:",
    event["iocs"]["ipv4"],
)

print(
    "Domains:",
    event["iocs"]["domains"],
)

print(
    "NVD records:",
    len(event["nvd"]),
)

print(
    "KEV records:",
    len(event["kev"]),
)

print(
    "Sources:",
    len(event["sources"]),
)

print(
    "Evidence reports:",
    len(
        event["evidence_reports"]
    ),
)

print(
    "\nAll correlation evidence tests passed."
)