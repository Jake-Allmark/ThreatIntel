import json

from ai.client import analyse_event
from collectors.multi import collect_all_feeds
from processing.correlate import correlate_records
from processing.kev import (
    build_kev_index,
    download_kev,
)
from processing.process import process_items


PRIORITY_ORDER = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "INFORMATIONAL": 1,
}


def get_priority_value(event):
    priority = event.get(
        "priority",
        {},
    )

    level = priority.get(
        "level",
        "INFORMATIONAL",
    )

    return PRIORITY_ORDER.get(
        level,
        0,
    )


def main():
    print(
        "Collecting threat intelligence..."
    )

    collection = collect_all_feeds(
        hours=24
    )

    print(
        "Reports collected:",
        len(collection["items"]),
    )

    print(
        "Loading CISA KEV..."
    )

    kev_index = build_kev_index(
        download_kev()
    )

    print(
        "Processing reports..."
    )

    processed = process_items(
        collection["items"],
        kev_index=kev_index,
    )

    successful = [
        event
        for event in processed
        if "processing_error" not in event
    ]

    print(
        "Reports processed:",
        len(successful),
    )

    print(
        "Correlating reports..."
    )

    events = correlate_records(
        successful
    )

    events.sort(
        key=get_priority_value,
        reverse=True,
    )

    if not events:
        print(
            "No threat events available."
        )
        return

    selected = events[0]

    priority = selected.get(
        "priority",
        {},
    )

    print()
    print(
        "SELECTED EVENT:"
    )

    print(
        selected.get(
            "title",
            "Untitled",
        )
    )

    print(
        "Priority:",
        priority.get(
            "level",
            "UNKNOWN",
        ),
    )

    print(
        "Score:",
        priority.get(
            "score",
            0,
        ),
    )

    print(
        "CVEs:",
        selected.get(
            "cves",
            [],
        ),
    )

    print(
        "Sources:",
        selected.get(
            "correlation",
            {},
        ).get(
            "source_count",
            1,
        ),
    )

    print()
    print(
        "Sending ONE event to Luna..."
    )

    result = analyse_event(
        selected
    )

    print()
    print(
        "AI ANALYSIS:"
    )

    print(
        json.dumps(
            result["analysis"],
            indent=2,
            default=str,
        )
    )

    print()
    print(
        "AI USAGE:"
    )

    print(
        json.dumps(
            result["usage"],
            indent=2,
        )
    )

    print(
        "Model:",
        result["model"],
    )


if __name__ == "__main__":
    main()