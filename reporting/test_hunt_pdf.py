import json
from pathlib import Path

from reporting.pdf import build_pdf


REPORT_PATH = Path(
    "reports/threatintel-hunt-integration-test.json"
)

HUNT_PATH = Path(
    "reports/threatintel-hunt-pack-test.json"
)

OUTPUT_PATH = Path(
    "reports/Threat-Intelligence-Hunt-PDF-Test.pdf"
)


with REPORT_PATH.open(
    "r",
    encoding="utf-8",
) as handle:
    report = json.load(
        handle
    )


with HUNT_PATH.open(
    "r",
    encoding="utf-8",
) as handle:
    hunt_pack = json.load(
        handle
    )


report["threat_hunts"] = [
    {
        "event_title": hunt_pack.get(
            "title",
            "Threat Hunt Test",
        ),
        "selection": {
            "score": 48,
            "behaviours": [
                {
                    "name": "malware_execution",
                }
            ],
            "telemetry": [
                "process",
                "file",
                "network",
            ],
            "reasons": [
                (
                    "Observable attacker behaviour "
                    "was identified."
                ),
                (
                    "Relevant to the managed "
                    "technology estate."
                ),
            ],
            "active_exploitation": True,
            "managed_estate_relevant": True,
        },
        "hunt_pack": hunt_pack,
    }
]


report["threat_hunt_summary"] = {
    "generated": 1,
    "maximum_per_run": 3,
    "review_required": True,
    "deployment_status": (
        "REVIEW BEFORE DEPLOYMENT"
    ),
}


build_pdf(
    report,
    OUTPUT_PATH,
)


print()
print("HUNT PDF TEST PASSED")
print("=" * 70)
print(OUTPUT_PATH.resolve())
print()
print("No OpenAI call was made.")