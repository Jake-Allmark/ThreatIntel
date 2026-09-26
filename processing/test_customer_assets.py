from processing.customer_assets import (
    correlate_customer_assets,
)


def make_event(
    title,
    *,
    summary="",
    cves=None,
    kev=None,
    active=False,
):
    return {
        "title": title,
        "summary": summary,
        "evidence_text": "",
        "evidence_reports": [],
        "cves": cves or [],
        "nvd": [],
        "kev": kev or [],
        "priority": {
            "active_exploitation_language": active,
        },
    }


def assert_match(
    event,
    expected_technology,
    expected_level,
):
    result = correlate_customer_assets(event)

    assert result["relevant"] is True

    matches = {
        item["technology"]: item["match_level"]
        for item in result["managed_technologies"]
    }

    assert expected_technology in matches, matches

    assert (
        matches[expected_technology]
        == expected_level
    ), matches


assert_match(
    make_event(
        "Fortinet patches FortiOS vulnerability",
        cves=["CVE-2026-11111"],
    ),
    "Fortinet",
    "PRODUCT_CVE",
)
print("PASS - Fortinet CVE match")


assert_match(
    make_event(
        "Cisco IOS XE vulnerability added to exploited catalogue",
        cves=["CVE-2026-22222"],
        kev=[
            {
                "cve_id": "CVE-2026-22222"
            }
        ],
    ),
    "Cisco",
    "PRODUCT_KEV",
)
print("PASS - Cisco KEV match")


assert_match(
    make_event(
        "Attackers actively exploiting SonicWall SMA vulnerability",
        cves=["CVE-2026-33333"],
        active=True,
    ),
    "SonicWall",
    "PRODUCT_ACTIVE_EXPLOITATION",
)
print("PASS - SonicWall exploitation match")


assert_match(
    make_event(
        "Veeam Backup & Replication security update released"
    ),
    "Veeam",
    "TECHNOLOGY",
)
print("PASS - Veeam technology match")


assert_match(
    make_event(
        "Microsoft Defender for Endpoint detection update"
    ),
    "Microsoft Defender",
    "TECHNOLOGY",
)
print("PASS - MDE match")


assert_match(
    make_event(
        "Google Chronicle detection engineering update"
    ),
    "Google Security Operations",
    "TECHNOLOGY",
)
print("PASS - Google SecOps match")


unrelated = correlate_customer_assets(
    make_event(
        "Researchers discuss a new Linux kernel fuzzing technique"
    )
)

assert unrelated["relevant"] is False
assert unrelated["exposure_confirmed"] is False

print("PASS - unrelated event does not match")


microsoft_event = correlate_customer_assets(
    make_event(
        "Windows Server vulnerability allows privilege escalation",
        cves=["CVE-2026-44444"],
    )
)

assert microsoft_event["exposure_confirmed"] is False
assert microsoft_event["requires_validation"] is True

print(
    "PASS - technology relevance does not claim customer exposure"
)


print()
print("All customer asset correlation tests passed.")