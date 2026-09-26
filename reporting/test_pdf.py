import json
from datetime import datetime
from pathlib import Path

from reporting.pdf import (
    build_pdf,
    split_events,
)


PROJECT_ROOT = (
    Path(__file__)
    .resolve()
    .parent
    .parent
)

INPUT_FILE = (
    PROJECT_ROOT
    / "reports"
    / "threatintel-relevance-test.json"
)


if not INPUT_FILE.exists():
    raise SystemExit(
        "Missing reclassified JSON report: "
        f"{INPUT_FILE}"
    )


with open(
    INPUT_FILE,
    "r",
    encoding="utf-8",
) as file:
    report = json.load(file)


events = report.get(
    "events",
    [],
)

threats, context, non_threat = (
    split_events(events)
)


# ------------------------------------------------------------
# Validate that we are NOT accidentally rendering stale data.
# ------------------------------------------------------------

if not threats:
    raise AssertionError(
        "No THREAT events found. "
        "The PDF test may be reading stale JSON."
    )

if not context:
    raise AssertionError(
        "No CONTEXT events found."
    )

if not non_threat:
    raise AssertionError(
        "No NON_THREAT events found."
    )


# ------------------------------------------------------------
# Build a dated filename from report generation time.
# ------------------------------------------------------------

generated_at = (
    report.get(
        "metadata",
        {},
    )
    .get(
        "generated_at",
        ""
    )
)

try:
    report_date = (
        datetime.fromisoformat(
            generated_at
        )
        .strftime(
            "%Y-%m-%d"
        )
    )

except (
    TypeError,
    ValueError,
):
    report_date = (
        datetime.now()
        .strftime(
            "%Y-%m-%d"
        )
    )


OUTPUT_FILE = (
    PROJECT_ROOT
    / "reports"
    / f"Threat-Intelligence-{report_date}.pdf"
)


# ------------------------------------------------------------
# Generate PDF.
# ------------------------------------------------------------

result = build_pdf(
    report,
    OUTPUT_FILE,
)


# ------------------------------------------------------------
# Basic PDF validation.
# ------------------------------------------------------------

assert OUTPUT_FILE.exists()

assert (
    OUTPUT_FILE.stat().st_size
    > 10_000
)

assert (
    OUTPUT_FILE.read_bytes()[:4]
    == b"%PDF"
)


print(
    f"PASS - Events: {len(events)}"
)

print(
    f"PASS - THREAT: {len(threats)}"
)

print(
    f"PASS - CONTEXT: {len(context)}"
)

print(
    f"PASS - NON_THREAT: {len(non_threat)}"
)

print(
    "PASS - PDF size: "
    f"{OUTPUT_FILE.stat().st_size:,} bytes"
)

print(
    f"PASS - PDF path: {result}"
)

print()
print(
    "Classification-aware PDF test passed."
)