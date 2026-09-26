import json
from pathlib import Path

from processing.customer_assets import (
    apply_customer_asset_correlation,
)
from processing.hunt_selector import (
    score_huntability,
    select_hunts,
)


INPUT_FILE = Path(
    "reports/threatintel-relevance-test.json"
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


print()
print("THREAT HUNT SELECTOR TEST")
print("=" * 70)
print(f"Events analysed: {len(events)}")


huntable = []


for event in events:
    relevance = (
        event.get(
            "relevance",
            {},
        )
        or {}
    )

    if (
        relevance.get("classification")
        != "THREAT"
    ):
        continue

    result = score_huntability(
        event
    )

    if result["huntable"]:
        huntable.append(
            (event, result)
        )


huntable.sort(
    key=lambda item: item[1]["score"],
    reverse=True,
)


print(
    f"Huntable THREAT events: "
    f"{len(huntable)}"
)

print()
print("HUNTABLE CANDIDATES")
print("-" * 70)


for event, result in huntable:
    behaviours = [
        item["name"]
        for item in result["behaviours"]
    ]

    print()
    print(
        f"{result['score']:>3} | "
        f"{result['priority']:<13} | "
        f"{event.get('title', 'Untitled')}"
    )

    print(
        "    Behaviours: "
        + ", ".join(behaviours)
    )

    print(
        "    Telemetry:  "
        + ", ".join(
            result["telemetry"]
        )
    )

    print(
        "    Managed estate: "
        + (
            "YES"
            if result[
                "managed_estate_relevant"
            ]
            else "NO"
        )
    )


selected = select_hunts(
    events,
    max_hunts=3,
)


print()
print("=" * 70)
print("SELECTED HUNT PACKS")
print("-" * 70)


for index, item in enumerate(
    selected,
    start=1,
):
    event = item["event"]
    result = item[
        "hunt_selection"
    ]

    print()
    print(f"HUNT {index}")
    print(
        f"Title: "
        f"{event.get('title', 'Untitled')}"
    )
    print(
        f"Huntability score: "
        f"{result['score']}"
    )
    print(
        f"Priority: "
        f"{result['priority']}"
    )
    print(
        "Managed estate: "
        + (
            "YES"
            if result[
                "managed_estate_relevant"
            ]
            else "NO"
        )
    )

    print(
        "Behaviours: "
        + ", ".join(
            behaviour["name"]
            for behaviour
            in result["behaviours"]
        )
    )

    print(
        "Telemetry: "
        + ", ".join(
            result["telemetry"]
        )
    )


# ---------------------------------------------------------
# Regression checks
# ---------------------------------------------------------

failures = []


if len(selected) > 3:
    failures.append(
        "More than 3 hunts were selected."
    )


for item in selected:
    event = item["event"]
    result = item[
        "hunt_selection"
    ]

    relevance = (
        event.get(
            "relevance",
            {},
        )
        or {}
    )

    if (
        relevance.get("classification")
        != "THREAT"
    ):
        failures.append(
            "Non-THREAT event selected: "
            + event.get(
                "title",
                "Untitled",
            )
        )

    if not result.get(
        "behaviours"
    ):
        failures.append(
            "Hunt selected without "
            "observable behaviour: "
            + event.get(
                "title",
                "Untitled",
            )
        )


# INFORMATIONAL threats must still be allowed
# when they contain strong huntable behaviour.

informational_test = {
    "title": (
        "ClickFix campaign uses PowerShell "
        "to execute credential stealer"
    ),
    "summary": (
        "Victims execute PowerShell which "
        "downloads a malware payload."
    ),
    "relevance": {
        "classification": "THREAT",
    },
    "priority": {
        "level": "INFORMATIONAL",
        "active_exploitation_language": False,
    },
    "customer_asset_exposure": {
        "relevant": False,
    },
}


info_result = score_huntability(
    informational_test
)


if not info_result["huntable"]:
    failures.append(
        "Behaviour-rich INFORMATIONAL "
        "threat was rejected."
    )


# A Critical CVE must not become a hunt merely
# because it has a high severity.

patch_only_test = {
    "title": (
        "Critical vulnerability fixed "
        "in Example Product"
    ),
    "summary": (
        "Affected versions should install "
        "the security update immediately."
    ),
    "relevance": {
        "classification": "THREAT",
    },
    "priority": {
        "level": "CRITICAL",
        "active_exploitation_language": False,
    },
    "customer_asset_exposure": {
        "relevant": True,
    },
    "cves": [
        "CVE-2099-12345",
    ],
}


patch_result = score_huntability(
    patch_only_test
)


if patch_result["huntable"]:
    failures.append(
        "Patch-only Critical CVE was "
        "incorrectly considered huntable."
    )


print()
print("=" * 70)
print("REGRESSION CHECKS")
print("-" * 70)


if failures:
    for failure in failures:
        print(
            "FAIL - " + failure
        )

    raise SystemExit(
        "FAIL - hunt selector needs adjustment."
    )


print(
    "PASS - maximum of 3 hunts enforced."
)
print(
    "PASS - hunts require observable behaviour."
)
print(
    "PASS - INFORMATIONAL threats can be hunt-worthy."
)
print(
    "PASS - Critical patch-only CVEs are not "
    "automatically hunt-worthy."
)

print()
print("No OpenAI calls were made.")