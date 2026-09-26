import json
from datetime import datetime


def collect_unique_cves(events):
    cves = set()

    for event in events:
        for cve in event.get(
            "cves",
            [],
        ):
            if cve:
                cves.add(
                    str(cve).upper()
                )

    return sorted(cves)


def count_kev_matches(events):
    cves = set()

    for event in events:
        for record in event.get(
            "kev",
            [],
        ):
            cve = record.get(
                "cve"
            )

            if cve:
                cves.add(
                    str(cve).upper()
                )

    return len(cves)


def count_candidate_iocs(events):
    values = set()

    for event in events:
        iocs = (
            event.get(
                "iocs",
                {},
            )
            or {}
        )

        for category, entries in (
            iocs.items()
        ):
            if not isinstance(
                entries,
                list,
            ):
                continue

            for value in entries:
                if value:
                    values.add(
                        (
                            category,
                            str(value),
                        )
                    )

    return len(values)


def build_priority_summary(events):
    counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "informational": 0,
    }

    for event in events:
        level = (
            event.get(
                "priority",
                {},
            )
            .get(
                "level",
                "INFORMATIONAL",
            )
            .lower()
        )

        if level not in counts:
            level = "informational"

        counts[level] += 1

    return counts


def make_json_safe(value):
    if isinstance(
        value,
        datetime,
    ):
        return value.isoformat()

    if isinstance(
        value,
        dict,
    ):
        return {
            str(key): make_json_safe(
                item
            )
            for key, item
            in value.items()
        }

    if isinstance(
        value,
        (
            list,
            tuple,
            set,
        ),
    ):
        return [
            make_json_safe(item)
            for item in value
        ]

    return value


def build_report(
    events,
    *,
    collection_hours,
    report_count,
    failures,
    ai_usage,
):
    priority_counts = (
        build_priority_summary(
            events
        )
    )

    cves = collect_unique_cves(
        events
    )

    summary = {
        **priority_counts,
        "cves": len(cves),
        "kev": count_kev_matches(
            events
        ),
        "candidate_iocs": (
            count_candidate_iocs(
                events
            )
        ),
    }

    metadata = {
        "schema_version": "1.0",
        "generated_at": (
            datetime.now()
            .astimezone()
            .isoformat()
        ),
        "collection_hours": (
            collection_hours
        ),
        "reports_collected": (
            report_count
        ),
        "correlated_events": (
            len(events)
        ),
        "source_failures": (
            len(failures)
        ),
        "failed_sources": (
            failures
        ),
        "ai_usage": ai_usage,
    }

    return make_json_safe(
        {
            "metadata": metadata,
            "summary": summary,
            "events": events,
        }
    )


def serialize_report(
    report,
    *,
    pretty=True,
):
    if pretty:
        return json.dumps(
            report,
            indent=2,
            ensure_ascii=False,
        )

    return json.dumps(
        report,
        separators=(
            ",",
            ":",
        ),
        ensure_ascii=False,
    )


def write_report(
    report,
    file_path,
    *,
    pretty=True,
):
    """
    Write a canonical ThreatIntel JSON report.

    Encoding is controlled directly by Python so
    Windows PowerShell redirection cannot silently
    convert the document to UTF-16 or add a BOM.
    """

    content = serialize_report(
        report,
        pretty=pretty,
    )

    with open(
        file_path,
        "w",
        encoding="utf-8",
        newline="\n",
    ) as file:
        file.write(
            content
        )

        file.write(
            "\n"
        )

    return file_path