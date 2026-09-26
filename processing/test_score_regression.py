from processing.score import calculate_priority


def check(name, condition):
    if not condition:
        raise AssertionError(
            f"FAIL - {name}"
        )

    print(
        f"PASS - {name}"
    )


# Regression 1:
# This wording appeared in the real PDF and was
# incorrectly scored as only MEDIUM.

wordpress = calculate_priority(
    {
        "title": (
            "Hackers start exploiting critical "
            "WordPress flaw for code execution"
        ),
        "summary": "",
        "nvd": [
            {
                "cve": "CVE-2026-12345",
                "cvss": {
                    "score": 9.8,
                },
            },
        ],
        "kev": [],
        "iocs": {},
    }
)

check(
    "start exploiting detected",
    wordpress[
        "active_exploitation_language"
    ] is True,
)

check(
    "start exploiting source is title",
    wordpress[
        "exploitation_evidence_source"
    ] == "event_title",
)

check(
    "start exploiting raises priority",
    wordpress["level"] == "HIGH"
    and wordpress["score"] == 45,
)


# Regression 2:
# Availability of exploit code is NOT equivalent
# to confirmed active exploitation.

ubuntu = calculate_priority(
    {
        "title": (
            "Exploit released for unpatched "
            "Ubuntu vulnerability"
        ),
        "summary": (
            "Researchers released exploit code "
            "for the vulnerability."
        ),
        "nvd": [
            {
                "cve": "CVE-2026-54321",
                "cvss": {
                    "score": 9.8,
                },
            },
        ],
        "kev": [],
        "iocs": {},
    }
)

check(
    "exploit release not active exploitation",
    ubuntu[
        "active_exploitation_language"
    ] is False,
)

check(
    "exploit release remains CVSS driven",
    ubuntu["level"] == "MEDIUM"
    and ubuntu["score"] == 15,
)


# Regression 3:
# Explicit negation must still override the word
# exploitation.

negated = calculate_priority(
    {
        "title": (
            "Critical vulnerability patched"
        ),
        "summary": (
            "There is no evidence of active "
            "exploitation."
        ),
        "nvd": [
            {
                "cve": "CVE-2026-99999",
                "cvss": {
                    "score": 9.8,
                },
            },
        ],
        "kev": [],
        "iocs": {},
    }
)

check(
    "negated exploitation remains false",
    negated[
        "active_exploitation_language"
    ] is False,
)

check(
    "negated event remains CVSS driven",
    negated["level"] == "MEDIUM"
    and negated["score"] == 15,
)


# Regression 4:
# Historical/background text in a full article
# must never escalate the event.

background = calculate_priority(
    {
        "title": (
            "Chrome security update released"
        ),
        "summary": (
            "Google released a new Chrome "
            "security update."
        ),
        "evidence_text": (
            "A separate vulnerability from an "
            "earlier release was actively "
            "exploited in attacks."
        ),
        "nvd": [],
        "kev": [],
        "iocs": {},
    }
)

check(
    "full article background ignored",
    background[
        "active_exploitation_language"
    ] is False,
)

check(
    "background article does not escalate",
    background["level"]
    == "INFORMATIONAL"
    and background["score"] == 0,
)


print()
print(
    "All scoring regression tests passed."
)