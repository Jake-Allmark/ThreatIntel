from processing.relevance import classify_relevance


def check(
    name,
    event,
    expected,
):
    result = classify_relevance(
        event
    )

    actual = result[
        "classification"
    ]

    if actual != expected:
        raise AssertionError(
            f"FAIL - {name}: "
            f"expected {expected}, "
            f"got {actual}. "
            f"Result={result}"
        )

    print(
        f"PASS - {name}: {actual}"
    )


def event(
    title,
    *,
    summary="",
    cves=None,
    kev=None,
    priority=None,
):
    return {
        "title": title,
        "summary": summary,
        "cves": cves or [],
        "kev": kev or [],
        "priority": priority or {
            "level": "INFORMATIONAL",
            "score": 0,
        },
        "evidence_reports": [],
    }


# ============================================================
# EXISTING OPERATIONAL THREAT TESTS
# ============================================================

check(
    "actively exploited vulnerability",
    event(
        "Hackers actively exploit WordPress vulnerability"
    ),
    "THREAT",
)

check(
    "CVE always threat",
    event(
        "Vendor releases security update",
        cves=[
            "CVE-2026-12345"
        ],
    ),
    "THREAT",
)

check(
    "KEV always threat",
    event(
        "Security advisory published",
        kev=[
            {
                "cve": "CVE-2026-12345"
            }
        ],
    ),
    "THREAT",
)

check(
    "ransomware incident",
    event(
        "Ransomware attack disrupts manufacturing company"
    ),
    "THREAT",
)

check(
    "FBI breach story",
    event(
        "ShinyHunters claims FBI breach and theft of applicant data"
    ),
    "THREAT",
)

check(
    "malware campaign",
    event(
        "New malware campaign targets cloud credentials"
    ),
    "THREAT",
)

check(
    "phishing campaign",
    event(
        "Phishing campaign targets Microsoft 365 users"
    ),
    "THREAT",
)


# ============================================================
# CONTEXT / NON-THREAT TESTS
# ============================================================

check(
    "Ryuk sentencing is context",
    event(
        "Ryuk operator sentenced to two years in prison"
    ),
    "CONTEXT",
)

check(
    "ransomware sentencing is context",
    event(
        "Ryuk ransomware operator sentenced to 2 years in prison"
    ),
    "CONTEXT",
)

check(
    "ransomware arrest is context",
    event(
        "Police arrest suspected ransomware operator"
    ),
    "CONTEXT",
)

check(
    "webinar is non threat",
    event(
        "Join our cybersecurity webinar next week"
    ),
    "NON_THREAT",
)

check(
    "virtual event is non threat",
    event(
        "Register now for our virtual event on cloud security"
    ),
    "NON_THREAT",
)

check(
    "funding story is non threat",
    event(
        "Cybersecurity startup raises $50 million in funding round"
    ),
    "NON_THREAT",
)

check(
    "survey story is non threat",
    event(
        "New survey reveals changing security priorities"
    ),
    "NON_THREAT",
)

check(
    "generic threat research is context",
    event(
        "Researchers publish annual threat landscape analysis"
    ),
    "CONTEXT",
)

check(
    "unknown security news defaults context",
    event(
        "Cybersecurity industry prepares for changes this year"
    ),
    "CONTEXT",
)

check(
    "deterministic CVE beats webinar wording",
    event(
        "Webinar discusses emergency patching guidance",
        cves=[
            "CVE-2026-99999"
        ],
    ),
    "THREAT",
)


# ============================================================
# LIVE-FEED REGRESSION TESTS
# ============================================================

check(
    "cPanel root code execution flaw",
    event(
        "New cPanel Flaw Lets a Hosting Account Run Code as Root, "
        "Take Full Server Control"
    ),
    "THREAT",
)

check(
    "Next.js server code execution flaw",
    event(
        "Critical Next.js ImageResponse Flaw Can Lead to Server "
        "Code Execution via Crafted SVG Input"
    ),
    "THREAT",
)

check(
    "Chrome vulnerability patch release",
    event(
        "Chrome 154 Patches 108 Vulnerabilities"
    ),
    "THREAT",
)

check(
    "Kubernetes configuration takeover",
    event(
        "How One Kubernetes YAML Can Hand Over a GCP Organization"
    ),
    "THREAT",
)

check(
    "GitLab unauthorized code execution path",
    event(
        "A Leaked GitLab Issue Email Address Lets Anyone Push Code "
        "and Run CI Jobs as You"
    ),
    "THREAT",
)

check(
    "GitLab supply chain attack path",
    event(
        "GitLab Email Addresses Can Be Weaponized for Supply Chain "
        "Attacks"
    ),
    "THREAT",
)


# ============================================================
# FALSE-POSITIVE REGRESSION TESTS
# ============================================================

check(
    "security testing methodology article",
    event(
        "How dynamic application security testing validates risk "
        "at runtime",
        summary=(
            "Learn how dynamic application security testing "
            "identifies vulnerabilities and validates security risk."
        ),
    ),
    "NON_THREAT",
)


print()
print(
    "All relevance tests passed."
)