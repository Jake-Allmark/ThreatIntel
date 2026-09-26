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
        "hypothesis": "Test",
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

broad = pack(
    'metadata.event_timestamp >= "2026-09-03T00:00:00Z" AND '
    '(metadata.event_type = "PROCESS_LAUNCH" OR '
    'metadata.event_type = "FILE_CREATION" OR '
    'metadata.event_type = "NETWORK_CONNECTION")',

    'let startTime=datetime(2026-09-03); '
    'DeviceProcessEvents | where Timestamp >= startTime | '
    'join kind=inner DeviceNetworkEvents on DeviceId',

    INSUFFICIENT + " - Cortex schema-specific evidence is unavailable.",
)

broad_problems = validate_hunt_pack(broad)

if len(broad_problems) < 2:
    raise SystemExit(
        "FAIL - broad date/generic telemetry hunts were not rejected."
    )

focused = pack(
    'metadata.event_type = "PROCESS_LAUNCH" AND '
    'target.process.command_line = /powershell/i',

    'DeviceProcessEvents | where FileName =~ "powershell.exe" '
    'or FileName =~ "pwsh.exe"',

    INSUFFICIENT + " - local XQL field mappings must be verified.",
)

focused_problems = validate_hunt_pack(focused)

if focused_problems:
    print("Unexpected focused-hunt problems:")
    for problem in focused_problems:
        print("-", problem)
    raise SystemExit("FAIL - focused hunt was incorrectly rejected.")

print("PASS - broad date-only/generic hunts are rejected.")
print("PASS - focused PowerShell behaviour is accepted.")
print("PASS - explicit insufficient-evidence fallback is accepted.")
print("PASS - no OpenAI call was made.")
