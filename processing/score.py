import re


EXPLOITATION_PATTERNS = [
    r"\bactively exploited\b",
    r"\bactively exploiting\b",
    r"\bactive exploitation\b",
    r"\bexploited in attacks\b",
    r"\bexploited in the wild\b",
    r"\bexploitation in the wild\b",
    r"\bobserved exploitation\b",
    r"\bconfirmed exploitation\b",
    r"\bunder active attack\b",
    r"\bused in attacks\b",
    r"\bbeing exploited\b",

    # Common current-exploitation wording.
    r"\bstart(?:s|ed|ing)? exploiting\b",
    r"\bbegin(?:s|ning|gan)? exploiting\b",
    r"\battackers exploit\b",
    r"\battackers exploiting\b",
    r"\bhackers exploit\b",
    r"\bhackers exploiting\b",
    r"\bthreat actors exploit\b",
    r"\bthreat actors exploiting\b",
    r"\bexploitation has started\b",
    r"\bexploitation has begun\b",
    r"\bexploitation observed\b",
]


NEGATION_PATTERNS = [
    r"\bnot actively exploited\b",
    r"\bnot actively exploiting\b",
    r"\bnot being exploited\b",
    r"\bnot exploited in the wild\b",
    r"\bno active exploitation\b",
    r"\bno evidence of active exploitation\b",
    r"\bno evidence of exploitation\b",
    r"\bno known exploitation\b",
    r"\bnot aware of exploitation\b",
    r"\bnot aware of any exploitation\b",
    r"\bno exploitation observed\b",
    r"\bexploitation not observed\b",
    r"\bhas not been exploited\b",
    r"\bhave not been exploited\b",
]


def normalize_text(value):
    if value is None:
        return ""

    text = str(value).lower()
    text = re.sub(r"\s+", " ", text)

    return text.strip()


def matches_any(text, patterns):
    return any(
        re.search(
            pattern,
            text,
            flags=re.IGNORECASE,
        )
        for pattern in patterns
    )


def has_negated_exploitation(text):
    normalized = normalize_text(text)

    if not normalized:
        return False

    return matches_any(
        normalized,
        NEGATION_PATTERNS,
    )


def has_exploitation_language(text):
    normalized = normalize_text(text)

    if not normalized:
        return False

    # Explicit negation always wins.
    if has_negated_exploitation(
        normalized
    ):
        return False

    return matches_any(
        normalized,
        EXPLOITATION_PATTERNS,
    )


def get_exploitation_evidence(record):
    """
    Look only at concise report-level fields.

    Deliberately DO NOT scan evidence_text or the
    complete article body. Long articles can mention
    unrelated historical exploitation and previously
    caused false priority escalation.
    """

    title = record.get("title")

    if has_exploitation_language(title):
        return {
            "matched": True,
            "source": "event_title",
            "text": title,
        }

    evidence_reports = (
        record.get("evidence_reports")
        or []
    )

    # Report titles first.
    for report in evidence_reports:
        if not isinstance(report, dict):
            continue

        report_title = report.get("title")

        if has_exploitation_language(
            report_title
        ):
            return {
                "matched": True,
                "source": "report_title",
                "text": report_title,
            }

    # Then report summaries.
    for report in evidence_reports:
        if not isinstance(report, dict):
            continue

        report_summary = report.get(
            "summary"
        )

        if has_exploitation_language(
            report_summary
        ):
            return {
                "matched": True,
                "source": "report_summary",
                "text": report_summary,
            }

    summary = record.get("summary")

    if has_exploitation_language(summary):
        return {
            "matched": True,
            "source": "event_summary",
            "text": summary,
        }

    return {
        "matched": False,
        "source": None,
        "text": None,
    }


def get_highest_cvss(record):
    highest = None

    for item in (
        record.get("nvd")
        or []
    ):
        if not isinstance(item, dict):
            continue

        if item.get("error"):
            continue

        cvss = item.get("cvss")

        if not isinstance(cvss, dict):
            continue

        score = cvss.get("score")

        try:
            score = float(score)
        except (TypeError, ValueError):
            continue

        if (
            highest is None
            or score > highest
        ):
            highest = score

    return highest


def get_kev_records(record):
    kev = (
        record.get("kev")
        or []
    )

    return [
        item
        for item in kev
        if isinstance(item, dict)
        and item.get("cve")
    ]


def has_known_ransomware_use(
    kev_records,
):
    """
    Support both our existing normalized KEV field
    and the longer upstream-style field name.
    """

    for item in kev_records:
        value = item.get(
            "ransomware_use"
        )

        if value is None:
            value = item.get(
                "known_ransomware_campaign_use",
                "",
            )

        normalized = str(
            value
        ).strip().lower()

        if normalized in {
            "known",
            "yes",
            "true",
        }:
            return True

    return False


def count_candidate_iocs(record):
    iocs = (
        record.get("iocs")
        or {}
    )

    if not isinstance(iocs, dict):
        return 0

    count = 0

    for values in iocs.values():
        if isinstance(values, list):
            count += len(values)

    return count


def calculate_priority(record):
    score = 0
    reasons = []

    highest_cvss = get_highest_cvss(
        record
    )

    # CVSS contributes urgency, but critical CVSS
    # alone must not create a CRITICAL event.
    if highest_cvss is not None:
        if highest_cvss >= 9.0:
            score += 15
            reasons.append(
                "Critical CVSS"
            )

        elif highest_cvss >= 7.0:
            score += 10
            reasons.append(
                "High CVSS"
            )

        elif highest_cvss >= 4.0:
            score += 5
            reasons.append(
                "Medium CVSS"
            )

    kev_records = get_kev_records(
        record
    )

    kev_match_count = len(
        kev_records
    )

    if kev_match_count:
        score += 20
        reasons.append(
            "CISA KEV"
        )

    exploitation = (
        get_exploitation_evidence(
            record
        )
    )

    active_exploitation = (
        exploitation["matched"]
    )

    if active_exploitation:
        score += 30
        reasons.append(
            "Current exploitation reported"
        )

    ransomware_use = (
        has_known_ransomware_use(
            kev_records
        )
    )

    if ransomware_use:
        score += 10
        reasons.append(
            "Known ransomware use"
        )

    potential_ioc_count = (
        count_candidate_iocs(
            record
        )
    )

    # Candidate IOCs do not affect priority.
    # Their presence alone does not prove
    # maliciousness.

    if (
        active_exploitation
        and score >= 55
    ):
        level = "CRITICAL"

    elif score >= 30:
        level = "HIGH"

    elif score >= 10:
        level = "MEDIUM"

    else:
        level = "INFORMATIONAL"

    return {
        "level": level,
        "score": score,
        "reasons": reasons,
        "highest_cvss": highest_cvss,
        "potential_ioc_count": (
            potential_ioc_count
        ),
        "active_exploitation_language": (
            active_exploitation
        ),
        "exploitation_evidence_source": (
            exploitation["source"]
        ),
        "kev_match_count": (
            kev_match_count
        ),
        "known_ransomware_use": (
            ransomware_use
        ),
    }