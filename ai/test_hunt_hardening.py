from ai.hunt_generator import (
    INSUFFICIENT,
    REVIEW_STATUS,
    validate_hunt_pack,
)


def section(query):
    return {
        "status": REVIEW_STATUS,
        "query": query,
        "what_it_looks_for": "test",
        "environment_notes": [],
    }


def pack(udm, kql, xql):
    return {
        "title": "Test hunt",
        "hypothesis": "Test hypothesis",
        "google_secops_udm": section(udm),
        "microsoft_defender_kql": section(kql),
        "cortex_xdr_xql": section(xql),
        "potential_false_positives": [],
        "analyst_validation": [],
        "confidence": "MEDIUM",
    }


print()
print("HUNT QUERY HARDENING TEST")
print("=" * 70)


# ---------------------------------------------------------
# TEST 1
# Broad queries should be rejected.
# ---------------------------------------------------------

broad = pack(
    'metadata.event_timestamp >= "2026-09-03T00:00:00Z" AND '
    '(metadata.event_type = "PROCESS_LAUNCH" OR '
    'metadata.event_type = "FILE_CREATION" OR '
    'metadata.event_type = "NETWORK_CONNECTION")',

    'let startTime=datetime(2026-09-03); '
    'DeviceProcessEvents '
    '| where Timestamp >= startTime '
    '| join kind=inner DeviceNetworkEvents on DeviceId',

    INSUFFICIENT
    + " - Cortex schema-specific evidence is unavailable.",
)

broad_problems = validate_hunt_pack(broad)

print()
print("BROAD QUERY VALIDATION")
print("-" * 70)

if broad_problems:
    for problem in broad_problems:
        print("-", problem)
else:
    print("NO PROBLEMS DETECTED")

print()
print(
    "Broad problems detected:",
    len(broad_problems),
)


if len(broad_problems) < 2:
    print()
    print(
        "FAIL - expected both the generic UDM and "
        "generic KQL queries to be rejected."
    )

    raise SystemExit(1)


print(
    "PASS - broad date/generic telemetry "
    "queries were rejected."
)


# ---------------------------------------------------------
# TEST 2
# Focused behavioural queries should be accepted.
# ---------------------------------------------------------

focused = pack(
    'metadata.event_type = "PROCESS_LAUNCH" AND '
    'target.process.command_line = /powershell/i',

    'DeviceProcessEvents '
    '| where FileName =~ "powershell.exe" '
    'or FileName =~ "pwsh.exe"',

    INSUFFICIENT
    + " - local XQL field mappings must be verified.",
)

focused_problems = validate_hunt_pack(
    focused
)

print()
print("FOCUSED QUERY VALIDATION")
print("-" * 70)

if focused_problems:

    for problem in focused_problems:
        print("-", problem)

    print()
    print(
        "FAIL - focused PowerShell hunt "
        "was incorrectly rejected."
    )

    raise SystemExit(1)


print(
    "PASS - focused PowerShell behaviour "
    "is accepted."
)


# ---------------------------------------------------------
# TEST 3
# Explicit insufficient-evidence fallback is valid.
# ---------------------------------------------------------

fallback = pack(
    INSUFFICIENT
    + " - insufficient UDM evidence.",

    INSUFFICIENT
    + " - insufficient Defender evidence.",

    INSUFFICIENT
    + " - insufficient Cortex evidence.",
)

fallback_problems = validate_hunt_pack(
    fallback
)

print()
print("INSUFFICIENT-EVIDENCE VALIDATION")
print("-" * 70)

if fallback_problems:

    for problem in fallback_problems:
        print("-", problem)

    print()
    print(
        "FAIL - explicit insufficient-evidence "
        "fallback was rejected."
    )

    raise SystemExit(1)


print(
    "PASS - explicit insufficient-evidence "
    "fallback is accepted."
)


print()
print("=" * 70)
print("ALL HARDENING TESTS PASSED")
print("No OpenAI call was made.")
print("=" * 70)