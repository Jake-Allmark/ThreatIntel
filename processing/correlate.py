import re
from difflib import SequenceMatcher

from processing.score import calculate_priority


STOP_WORDS = {
    "a",
    "an",
    "and",
    "are",
    "as",
    "at",
    "be",
    "been",
    "by",
    "for",
    "from",
    "has",
    "have",
    "in",
    "into",
    "is",
    "it",
    "its",
    "of",
    "on",
    "or",
    "that",
    "the",
    "their",
    "this",
    "to",
    "with",
    "after",
    "over",
    "new",
    "critical",
    "security",
    "vulnerability",
    "vulnerabilities",
    "flaw",
    "flaws",
}


DISTINCTIVE_EVENT_TOKENS = {
    "attack",
    "attacks",
    "breach",
    "breached",
    "compromise",
    "compromised",
    "exploit",
    "exploited",
    "hackers",
    "malware",
    "phishing",
    "prison",
    "ransomware",
    "sentence",
    "sentenced",
    "stolen",
    "zero-day",
}


def normalize_title(title):
    title = str(
        title or ""
    ).lower()

    #
    # Normalize equivalent time expressions.
    #
    title = re.sub(
        r"\b24[- ]hours?\b",
        "1 day",
        title,
    )

    title = re.sub(
        r"\b24[- ]months?\b",
        "2 years",
        title,
    )

    title = re.sub(
        r"\btwo[- ]years?\b",
        "2 years",
        title,
    )

    #
    # Normalize common event/action word variants.
    #
    replacements = {
        "sentenced": "sentence",
        "sentencing": "sentence",
        "breached": "breach",
        "breaches": "breach",
        "attacks": "attack",
        "attacked": "attack",
        "attacking": "attack",
        "exploits": "exploit",
        "exploited": "exploit",
        "exploiting": "exploit",
        "compromises": "compromise",
        "compromised": "compromise",
        "compromising": "compromise",
        "operators": "operator",
        "members": "member",
        "claims": "claim",
        "claimed": "claim",
    }

    for old, new in replacements.items():
        title = re.sub(
            rf"\b{re.escape(old)}\b",
            new,
            title,
        )

    title = re.sub(
        r"[^a-z0-9\s-]",
        " ",
        title,
    )

    title = re.sub(
        r"\s+",
        " ",
        title,
    )

    return title.strip()


def title_similarity(
    title_a,
    title_b,
):
    a = normalize_title(
        title_a
    )

    b = normalize_title(
        title_b
    )

    if not a or not b:
        return 0.0

    return SequenceMatcher(
        None,
        a,
        b,
    ).ratio()


def title_tokens(title):
    normalized = normalize_title(
        title
    )

    tokens = set()

    for token in normalized.split():
        if token in STOP_WORDS:
            continue

        if len(token) < 3:
            continue

        tokens.add(
            token
        )

    return tokens


def title_token_similarity(
    title_a,
    title_b,
):
    a = title_tokens(
        title_a
    )

    b = title_tokens(
        title_b
    )

    if not a or not b:
        return {
            "jaccard": 0.0,
            "shared_tokens": [],
            "shared_count": 0,
        }

    shared = a & b
    union = a | b

    return {
        "jaccard": (
            len(shared) / len(union)
            if union
            else 0.0
        ),
        "shared_tokens": sorted(
            shared
        ),
        "shared_count": len(
            shared
        ),
    }


def has_distinctive_shared_token(
    shared_tokens,
):
    normalized_event_tokens = {
        normalize_title(token)
        for token in DISTINCTIVE_EVENT_TOKENS
    }

    return bool(
        set(shared_tokens)
        & normalized_event_tokens
    )


def get_cve_set(record):
    return {
        str(cve).upper()
        for cve in record.get(
            "cves",
            [],
        )
        if cve
    }


def shared_cves(
    record_a,
    record_b,
):
    return sorted(
        get_cve_set(record_a)
        & get_cve_set(record_b)
    )


def source_from_record(record):
    return {
        "source": record.get(
            "source",
            "Unknown",
        ),
        "title": record.get(
            "title",
            "",
        ),
        "url": record.get(
            "url",
            "",
        ),
        "published_at": record.get(
            "published_at"
        ),
    }


def evidence_from_record(record):
    return {
        "source": record.get(
            "source",
            "Unknown",
        ),
        "title": record.get(
            "title",
            "",
        ),
        "url": record.get(
            "url",
            "",
        ),
        "published_at": record.get(
            "published_at"
        ),
        "summary": record.get(
            "summary",
            "",
        ),
        "evidence_text": record.get(
            "evidence_text",
            "",
        ),
        "cves": record.get(
            "cves",
            [],
        ),
        "iocs": record.get(
            "iocs",
            {},
        ),
    }


def ensure_sources(record):
    sources = record.setdefault(
        "sources",
        [],
    )

    primary = source_from_record(
        record
    )

    existing_urls = {
        source.get("url")
        for source in sources
    }

    if (
        primary["url"]
        not in existing_urls
    ):
        sources.insert(
            0,
            primary,
        )

    return sources


def ensure_evidence_reports(record):
    reports = record.setdefault(
        "evidence_reports",
        [],
    )

    primary = evidence_from_record(
        record
    )

    existing_urls = {
        report.get("url")
        for report in reports
    }

    if (
        primary["url"]
        not in existing_urls
    ):
        reports.insert(
            0,
            primary,
        )

    return reports


def merge_unique_strings(
    primary_values,
    duplicate_values,
):
    combined = list(
        primary_values or []
    )

    existing = {
        str(value).lower()
        for value in combined
    }

    for value in (
        duplicate_values or []
    ):
        key = str(
            value
        ).lower()

        if key in existing:
            continue

        combined.append(
            value
        )

        existing.add(
            key
        )

    return combined


def merge_iocs(
    primary_iocs,
    duplicate_iocs,
):
    primary_iocs = (
        primary_iocs
        if isinstance(
            primary_iocs,
            dict,
        )
        else {}
    )

    duplicate_iocs = (
        duplicate_iocs
        if isinstance(
            duplicate_iocs,
            dict,
        )
        else {}
    )

    result = {}

    fields = (
        "ipv4",
        "domains",
        "urls",
        "md5",
        "sha1",
        "sha256",
    )

    for field in fields:
        result[field] = (
            merge_unique_strings(
                primary_iocs.get(
                    field,
                    [],
                ),
                duplicate_iocs.get(
                    field,
                    [],
                ),
            )
        )

    return result


def record_quality(record):
    """
    Prefer successful enrichment records over
    error placeholders for the same CVE.
    """

    if not isinstance(
        record,
        dict,
    ):
        return -100

    if record.get(
        "error"
    ):
        return -10

    score = 0

    for key in (
        "cvss",
        "description",
        "weaknesses",
        "references",
        "configurations",
        "date_added",
        "required_action",
        "ransomware_use",
        "known_ransomware_campaign_use",
    ):
        value = record.get(
            key
        )

        if value not in (
            None,
            "",
            [],
            {},
        ):
            score += 1

    return score


def merge_records_by_key(
    primary_records,
    duplicate_records,
    key_name,
):
    """
    Merge structured records such as NVD and KEV.

    If duplicate records represent the same CVE,
    keep the higher-quality record.
    """

    ordered_keys = []
    records_by_key = {}
    keyless_records = []

    for record in list(
        primary_records or []
    ) + list(
        duplicate_records or []
    ):
        if not isinstance(
            record,
            dict,
        ):
            continue

        key = record.get(
            key_name
        )

        if not key:
            keyless_records.append(
                record
            )
            continue

        normalized_key = str(
            key
        ).upper()

        if (
            normalized_key
            not in records_by_key
        ):
            records_by_key[
                normalized_key
            ] = record

            ordered_keys.append(
                normalized_key
            )

            continue

        existing = records_by_key[
            normalized_key
        ]

        if (
            record_quality(record)
            > record_quality(existing)
        ):
            records_by_key[
                normalized_key
            ] = record

    combined = [
        records_by_key[key]
        for key in ordered_keys
    ]

    combined.extend(
        keyless_records
    )

    return combined


def merge_deterministic_evidence(
    primary,
    duplicate,
):
    primary["cves"] = (
        merge_unique_strings(
            primary.get(
                "cves",
                [],
            ),
            duplicate.get(
                "cves",
                [],
            ),
        )
    )

    primary["iocs"] = merge_iocs(
        primary.get(
            "iocs",
            {},
        ),
        duplicate.get(
            "iocs",
            {},
        ),
    )

    primary["nvd"] = (
        merge_records_by_key(
            primary.get(
                "nvd",
                [],
            ),
            duplicate.get(
                "nvd",
                [],
            ),
            "cve",
        )
    )

    primary["kev"] = (
        merge_records_by_key(
            primary.get(
                "kev",
                [],
            ),
            duplicate.get(
                "kev",
                [],
            ),
            "cve",
        )
    )

    return primary


def rebuild_combined_evidence(record):
    combined = []

    for report in record.get(
        "evidence_reports",
        [],
    ):
        text = report.get(
            "evidence_text",
            "",
        )

        if not text:
            continue

        if text in combined:
            continue

        combined.append(
            text
        )

    record["evidence_text"] = (
        "\n\n".join(
            combined
        )
    )

    return record


def should_correlate(
    record_a,
    record_b,
):
    cves_a = get_cve_set(
        record_a
    )

    cves_b = get_cve_set(
        record_b
    )

    shared = sorted(
        cves_a & cves_b
    )

    similarity = title_similarity(
        record_a.get(
            "title",
            "",
        ),
        record_b.get(
            "title",
            "",
        ),
    )

    token_match = (
        title_token_similarity(
            record_a.get(
                "title",
                "",
            ),
            record_b.get(
                "title",
                "",
            ),
        )
    )

    token_jaccard = (
        token_match[
            "jaccard"
        ]
    )

    shared_tokens = (
        token_match[
            "shared_tokens"
        ]
    )

    shared_token_count = (
        token_match[
            "shared_count"
        ]
    )

    distinctive_event_overlap = (
        has_distinctive_shared_token(
            shared_tokens
        )
    )

    #
    # CASE 1:
    # Both reports contain exactly one
    # identical CVE.
    #
    if (
        len(cves_a) == 1
        and len(cves_b) == 1
        and shared
    ):
        return {
            "match": True,
            "strength": "strong",
            "reason": "same_single_cve",
            "shared_cves": shared,
            "title_similarity": similarity,
            "token_similarity": token_jaccard,
            "shared_title_tokens": shared_tokens,
        }

    #
    # CASE 2:
    # Reports have CVE evidence.
    #
    if shared:
        smaller_set_size = min(
            len(cves_a),
            len(cves_b),
        )

        overlap_ratio = (
            len(shared)
            / smaller_set_size
            if smaller_set_size
            else 0.0
        )

        if (
            len(shared) >= 2
            and overlap_ratio >= 0.50
        ):
            return {
                "match": True,
                "strength": "strong",
                "reason": (
                    "substantial_cve_overlap"
                ),
                "shared_cves": shared,
                "cve_overlap_ratio": overlap_ratio,
                "title_similarity": similarity,
                "token_similarity": token_jaccard,
                "shared_title_tokens": shared_tokens,
            }

        smaller_is_subset = (
            bool(cves_a)
            and bool(cves_b)
            and (
                cves_a.issubset(cves_b)
                or cves_b.issubset(cves_a)
            )
        )

        #
        # A common news-reporting pattern:
        #
        # Report A covers one CVE.
        # Report B covers the same CVE plus related
        # vulnerabilities in the same incident.
        #
        if (
            smaller_is_subset
            and overlap_ratio == 1.0
            and (
                similarity >= 0.55
                or (
                    shared_token_count >= 3
                    and token_jaccard >= 0.20
                )
            )
        ):
            return {
                "match": True,
                "strength": "moderate",
                "reason": (
                    "cve_subset_and_similar_title"
                ),
                "shared_cves": shared,
                "cve_overlap_ratio": overlap_ratio,
                "title_similarity": similarity,
                "token_similarity": token_jaccard,
                "shared_title_tokens": shared_tokens,
            }

        if similarity >= 0.90:
            return {
                "match": True,
                "strength": "moderate",
                "reason": (
                    "shared_cve_and_similar_title"
                ),
                "shared_cves": shared,
                "cve_overlap_ratio": overlap_ratio,
                "title_similarity": similarity,
                "token_similarity": token_jaccard,
                "shared_title_tokens": shared_tokens,
            }

        return {
            "match": False,
            "strength": "ambiguous",
            "reason": (
                "insufficient_cve_overlap"
            ),
            "shared_cves": shared,
            "cve_overlap_ratio": overlap_ratio,
            "title_similarity": similarity,
            "token_similarity": token_jaccard,
            "shared_title_tokens": shared_tokens,
        }

    #
    # CASE 3:
    # No CVEs, but almost identical titles.
    #
    if similarity >= 0.92:
        return {
            "match": True,
            "strength": "moderate",
            "reason": (
                "very_similar_title"
            ),
            "shared_cves": [],
            "title_similarity": similarity,
            "token_similarity": token_jaccard,
            "shared_title_tokens": shared_tokens,
        }

    #
    # CASE 4:
    # No CVEs and differently worded news reports.
    #
    # Require:
    #
    # - at least 3 meaningful shared title tokens
    # - at least 20% token overlap
    # - at least one shared event/action token
    #
    # OR:
    #
    # - at least 4 meaningful shared title tokens
    # - at least 20% token overlap
    #
    # This catches differently phrased reports about
    # the same Ryuk/ShinyHunters incidents without
    # merging stories merely because they share a
    # vendor or generic cybersecurity word.
    #
    if (
        token_jaccard >= 0.20
        and (
            (
                shared_token_count >= 3
                and distinctive_event_overlap
            )
            or shared_token_count >= 4
        )
    ):
        return {
            "match": True,
            "strength": "moderate",
            "reason": (
                "distinctive_title_token_overlap"
            ),
            "shared_cves": [],
            "title_similarity": similarity,
            "token_similarity": token_jaccard,
            "shared_title_tokens": shared_tokens,
        }

    return {
        "match": False,
        "strength": None,
        "reason": None,
        "shared_cves": [],
        "title_similarity": similarity,
        "token_similarity": token_jaccard,
        "shared_title_tokens": shared_tokens,
    }


def merge_records(
    primary,
    duplicate,
    match,
):
    sources = ensure_sources(
        primary
    )

    duplicate_source = (
        source_from_record(
            duplicate
        )
    )

    existing_source_urls = {
        source.get("url")
        for source in sources
    }

    if (
        duplicate_source["url"]
        not in existing_source_urls
    ):
        sources.append(
            duplicate_source
        )

    evidence_reports = (
        ensure_evidence_reports(
            primary
        )
    )

    duplicate_evidence = (
        evidence_from_record(
            duplicate
        )
    )

    existing_report_urls = {
        report.get("url")
        for report in evidence_reports
    }

    if (
        duplicate_evidence["url"]
        not in existing_report_urls
    ):
        evidence_reports.append(
            duplicate_evidence
        )

    merge_deterministic_evidence(
        primary,
        duplicate,
    )

    rebuild_combined_evidence(
        primary
    )

    #
    # Recalculate priority after correlation.
    #
    primary["priority"] = (
        calculate_priority(
            primary
        )
    )

    correlation = primary.setdefault(
        "correlation",
        {},
    )

    matches = correlation.setdefault(
        "matches",
        [],
    )

    matches.append(
        {
            "source": duplicate.get(
                "source",
                "Unknown",
            ),
            "url": duplicate.get(
                "url",
                "",
            ),
            "strength": match.get(
                "strength"
            ),
            "reason": match.get(
                "reason"
            ),
            "shared_cves": match.get(
                "shared_cves",
                [],
            ),
            "cve_overlap_ratio": (
                match.get(
                    "cve_overlap_ratio"
                )
            ),
            "title_similarity": (
                match.get(
                    "title_similarity",
                    0.0,
                )
            ),
            "token_similarity": (
                match.get(
                    "token_similarity",
                    0.0,
                )
            ),
            "shared_title_tokens": (
                match.get(
                    "shared_title_tokens",
                    [],
                )
            ),
        }
    )

    correlation[
        "source_count"
    ] = len(
        sources
    )

    correlation[
        "evidence_report_count"
    ] = len(
        evidence_reports
    )

    return primary


def correlate_records(records):
    """
    Correlate reports conservatively.

    Prefer displaying a duplicate over performing
    an unsafe false-positive merge.
    """

    correlated = []

    for candidate in records:
        if (
            "processing_error"
            in candidate
        ):
            correlated.append(
                candidate
            )
            continue

        ensure_sources(
            candidate
        )

        ensure_evidence_reports(
            candidate
        )

        candidate.setdefault(
            "correlation",
            {},
        )

        candidate[
            "correlation"
        ].setdefault(
            "matches",
            [],
        )

        candidate[
            "correlation"
        ][
            "source_count"
        ] = len(
            candidate["sources"]
        )

        candidate[
            "correlation"
        ][
            "evidence_report_count"
        ] = len(
            candidate[
                "evidence_reports"
            ]
        )

        matched = False

        for primary in correlated:
            if (
                "processing_error"
                in primary
            ):
                continue

            match = should_correlate(
                primary,
                candidate,
            )

            if not match[
                "match"
            ]:
                continue

            merge_records(
                primary,
                candidate,
                match,
            )

            matched = True
            break

        if not matched:
            correlated.append(
                candidate
            )

    return correlated