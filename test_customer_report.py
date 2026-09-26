import json
from pathlib import Path

from processing.customer_assets import (
    apply_customer_asset_correlation,
)


INPUT_FILE = Path(
    "reports/threatintel-relevance-test.json"
)

OUTPUT_FILE = Path(
    "reports/threatintel-customer-test.json"
)


if not INPUT_FILE.exists():
    raise SystemExit(
        f"ERROR - missing {INPUT_FILE}"
    )


with INPUT_FILE.open(
    "r",
    encoding="utf-8",
) as file:
    report = json.load(file)


events = report.get(
    "events",
    [],
)


apply_customer_asset_correlation(
    events
)


matched_events = []

technology_counts = {}


for event in events:
    exposure = event.get(
        "customer_asset_exposure",
        {},
    )

    if not exposure.get(
        "relevant",
        False,
    ):
        continue

    matched_events.append(
        event
    )

    for match in exposure.get(
        "managed_technologies",
        [],
    ):
        technology = match.get(
            "technology",
            "Unknown",
        )

        technology_counts[
            technology
        ] = (
            technology_counts.get(
                technology,
                0,
            )
            + 1
        )


with OUTPUT_FILE.open(
    "w",
    encoding="utf-8",
) as file:
    json.dump(
        report,
        file,
        indent=2,
        ensure_ascii=False,
    )


print()
print(
    "CUSTOMER ASSET CORRELATION TEST"
)

print(
    "=" * 60
)

print(
    f"Events analysed: {len(events)}"
)

print(
    "Managed-estate relevant: "
    f"{len(matched_events)}"
)

print()


print(
    "TECHNOLOGY MATCHES"
)

print(
    "-" * 60
)


for technology, count in sorted(
    technology_counts.items(),
    key=lambda item: (
        -item[1],
        item[0].lower(),
    ),
):
    print(
        f"{technology:<32} {count}"
    )


print()
print(
    "MATCHED THREAT EVENTS"
)

print(
    "-" * 60
)


for event in matched_events:
    relevance = (
        event.get(
            "relevance",
            {},
        )
        .get(
            "classification",
            "UNKNOWN",
        )
    )

    if relevance != "THREAT":
        continue

    priority = (
        event.get(
            "priority",
            {},
        )
        .get(
            "level",
            "INFORMATIONAL",
        )
    )

    exposure = event[
        "customer_asset_exposure"
    ]

    technologies = []

    for match in exposure.get(
        "managed_technologies",
        [],
    ):
        technologies.append(
            (
                f"{match['technology']} "
                f"[{match['match_level']}]"
            )
        )

    print()
    print(
        f"{priority}: "
        f"{event.get('title', 'Untitled')}"
    )

    print(
        "  Managed estate: "
        + ", ".join(
            technologies
        )
    )


print()
print(
    "=" * 60
)

print(
    "IMPORTANT:"
)

print(
    "Matches indicate managed-technology "
    "relevance only."
)

print(
    "They do NOT confirm that any customer "
    "is vulnerable."
)

print()

print(
    "PASS - customer correlation report written:"
)

print(
    OUTPUT_FILE.resolve()
)