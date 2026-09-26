from processing.correlate import (
    correlate_records,
    merge_records_by_key,
    should_correlate,
)


def check(name, condition):
    if not condition:
        raise AssertionError(
            f"FAIL - {name}"
        )

    print(
        f"PASS - {name}"
    )


def event(
    title,
    url,
    *,
    cves=None,
):
    return {
        "source": "Test Source",
        "title": title,
        "url": url,
        "published_at": None,
        "summary": "",
        "evidence_text": "",
        "cves": cves or [],
        "iocs": {},
        "nvd": [],
        "kev": [],
        "priority": {
            "level": "INFORMATIONAL",
            "score": 0,
        },
        "correlation": {
            "matches": [],
            "source_count": 1,
            "evidence_report_count": 1,
        },
    }


# --------------------------------------------------
# TEST 1
# Arista / VeloCloud duplicate from the real PDF.
# One article has several CVEs, while another article
# about the same incident contains only one of them.
# --------------------------------------------------

arista_a = event(
    (
        "Arista patches actively exploited "
        "VeloCloud Orchestrator zero-day"
    ),
    "https://example.com/arista-a",
    cves=[
        "CVE-2026-16812",
        "CVE-2026-7473",
        "CVE-2026-93952",
    ],
)

arista_b = event(
    (
        "Arista Urges Immediate Patching of "
        "Exploited VCO Zero-Day"
    ),
    "https://example.com/arista-b",
    cves=[
        "CVE-2026-93952",
    ],
)

match = should_correlate(
    arista_a,
    arista_b,
)

check(
    "Arista subset CVE reports correlate",
    match["match"] is True,
)


# --------------------------------------------------
# TEST 2
# Ryuk sentencing duplicate reporting.
# --------------------------------------------------

ryuk_a = event(
    (
        "Ryuk ransomware operator sentenced "
        "to 2 years in prison"
    ),
    "https://example.com/ryuk-a",
)

ryuk_b = event(
    (
        "Ryuk ransomware operator gets "
        "2-year sentence after extorting "
        "victims for $1.2 million"
    ),
    "https://example.com/ryuk-b",
)

ryuk_c = event(
    (
        "Ryuk ransomware member sentenced "
        "to 24 months in prison"
    ),
    "https://example.com/ryuk-c",
)

check(
    "Ryuk A and B correlate",
    should_correlate(
        ryuk_a,
        ryuk_b,
    )["match"] is True,
)

check(
    "Ryuk A and C correlate",
    should_correlate(
        ryuk_a,
        ryuk_c,
    )["match"] is True,
)


# --------------------------------------------------
# TEST 3
# ShinyHunters / FBI duplicate reporting.
# --------------------------------------------------

shiny_a = event(
    (
        "FBI investigating alleged "
        "ShinyHunters breach of its jobs site"
    ),
    "https://example.com/shiny-a",
)

shiny_b = event(
    (
        "ShinyHunters Claims FBI Breach, "
        "Says It Stole Data on Agents "
        "and Job Applicants"
    ),
    "https://example.com/shiny-b",
)

shiny_c = event(
    (
        "ShinyHunters claims attack on FBI "
        "exposes almost all agents"
    ),
    "https://example.com/shiny-c",
)

check(
    "ShinyHunters A and B correlate",
    should_correlate(
        shiny_a,
        shiny_b,
    )["match"] is True,
)

check(
    "ShinyHunters B and C correlate",
    should_correlate(
        shiny_b,
        shiny_c,
    )["match"] is True,
)


# --------------------------------------------------
# TEST 4
# Different Microsoft stories must NOT be merged
# simply because they mention Microsoft/security.
# --------------------------------------------------

unrelated_a = event(
    (
        "Microsoft patches Exchange "
        "authentication vulnerability"
    ),
    "https://example.com/microsoft-a",
)

unrelated_b = event(
    (
        "Microsoft announces new Defender "
        "security capabilities"
    ),
    "https://example.com/microsoft-b",
)

check(
    "unrelated Microsoft stories stay separate",
    should_correlate(
        unrelated_a,
        unrelated_b,
    )["match"] is False,
)


# --------------------------------------------------
# TEST 5
# Generic ransomware stories about different victims
# must NOT be merged.
# --------------------------------------------------

ransomware_a = event(
    (
        "Ransomware attack disrupts "
        "manufacturing company"
    ),
    "https://example.com/ransomware-a",
)

ransomware_b = event(
    (
        "Ransomware attack hits "
        "regional healthcare provider"
    ),
    "https://example.com/ransomware-b",
)

check(
    "generic ransomware stories stay separate",
    should_correlate(
        ransomware_a,
        ransomware_b,
    )["match"] is False,
)


# --------------------------------------------------
# TEST 6
# If one source got an NVD error but another source
# obtained a proper record for the same CVE, the
# successful record should win.
# --------------------------------------------------

bad_nvd = {
    "cve": "CVE-2026-12345",
    "error": "temporary NVD failure",
}

good_nvd = {
    "cve": "CVE-2026-12345",
    "description": "Real NVD record",
    "cvss": {
        "score": 9.8,
    },
}

merged_nvd = merge_records_by_key(
    [bad_nvd],
    [good_nvd],
    "cve",
)

check(
    "good NVD record replaces error record",
    len(merged_nvd) == 1
    and not merged_nvd[0].get(
        "error"
    )
    and merged_nvd[0].get(
        "description"
    ) == "Real NVD record",
)


# --------------------------------------------------
# TEST 7
# All three Ryuk articles should ultimately become
# one correlated event.
# --------------------------------------------------

correlated_ryuk = correlate_records(
    [
        ryuk_a,
        ryuk_b,
        ryuk_c,
    ]
)

check(
    "three Ryuk reports become one event",
    len(correlated_ryuk) == 1,
)

check(
    "Ryuk event preserves three sources",
    correlated_ryuk[0][
        "correlation"
    ][
        "source_count"
    ] == 3,
)


print()
print(
    "All correlation regression tests passed."
)