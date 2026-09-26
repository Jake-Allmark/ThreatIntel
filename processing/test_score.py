from processing.score import (
    calculate_priority,
)


def nvd(score):
    return {
        "cve": "CVE-2026-12345",
        "cvss": {
            "score": score,
        },
    }


def kev(ransomware_use="Unknown"):
    return {
        "cve": "CVE-2026-12345",
        "ransomware_use": ransomware_use,
    }


# TEST 1 - Critical CVSS alone

result = calculate_priority(
    {
        "title": "Critical vulnerability",
        "nvd": [nvd(9.8)],
        "kev": [],
        "iocs": {},
    }
)

assert result["level"] == "MEDIUM"
assert result["score"] == 15

print("PASS - critical CVSS alone")


# TEST 2 - KEV alone

result = calculate_priority(
    {
        "title": "Known vulnerability",
        "nvd": [],
        "kev": [kev()],
        "iocs": {},
    }
)

assert result["level"] == "MEDIUM"
assert result["score"] == 20

print("PASS - KEV alone")


# TEST 3 - Critical CVSS + KEV

result = calculate_priority(
    {
        "title": "Critical vulnerability",
        "nvd": [nvd(9.8)],
        "kev": [kev()],
        "iocs": {},
    }
)

assert result["level"] == "HIGH"
assert result["score"] == 35

print("PASS - CVSS plus KEV")


# TEST 4 - Exploitation in event title

result = calculate_priority(
    {
        "title": (
            "Attackers actively exploited "
            "the vulnerability"
        ),
        "nvd": [],
        "kev": [],
        "iocs": {},
    }
)

assert result["level"] == "HIGH"
assert result["score"] == 30

assert (
    result["exploitation_evidence_source"]
    == "event_title"
)

print("PASS - exploitation in title")


# TEST 5 - CVSS + KEV + exploitation

result = calculate_priority(
    {
        "title": (
            "Critical flaw actively exploited "
            "in attacks"
        ),
        "nvd": [nvd(9.8)],
        "kev": [kev()],
        "iocs": {},
    }
)

assert result["level"] == "CRITICAL"
assert result["score"] == 65

print("PASS - grounded critical event")


# TEST 6 - Ransomware evidence

result = calculate_priority(
    {
        "title": "Critical vulnerability",
        "nvd": [nvd(9.8)],
        "kev": [
            kev("Known"),
        ],
        "iocs": {},
    }
)

assert result["level"] == "HIGH"
assert result["score"] == 45

print("PASS - ransomware evidence")


# TEST 7 - Background article text ignored

result = calculate_priority(
    {
        "title": (
            "Chrome 154 Patches "
            "108 Vulnerabilities"
        ),
        "summary": (
            "Google released security "
            "updates for Chrome."
        ),
        "evidence_text": (
            "Background information says an "
            "unrelated vulnerability was "
            "actively exploited in attacks."
        ),
        "nvd": [],
        "kev": [],
        "iocs": {},
    }
)

assert (
    result["active_exploitation_language"]
    is False
)

assert result["level"] == "INFORMATIONAL"
assert result["score"] == 0

print(
    "PASS - background article text ignored"
)


# TEST 8 - Negation respected

result = calculate_priority(
    {
        "title": (
            "Vendor patches vulnerability"
        ),
        "summary": (
            "The vendor is not aware of "
            "exploitation in the wild."
        ),
        "nvd": [nvd(9.8)],
        "kev": [],
        "iocs": {},
    }
)

assert (
    result["active_exploitation_language"]
    is False
)

assert result["score"] == 15
assert result["level"] == "MEDIUM"

print(
    "PASS - exploitation negation respected"
)


# TEST 9 - Report summary exploitation

result = calculate_priority(
    {
        "title": "Security update",
        "evidence_reports": [
            {
                "title": "Security update",
                "summary": (
                    "The vulnerability is being "
                    "exploited in attacks."
                ),
            },
        ],
        "nvd": [nvd(9.8)],
        "kev": [kev()],
        "iocs": {},
    }
)

assert result["level"] == "CRITICAL"
assert result["score"] == 65

assert (
    result["exploitation_evidence_source"]
    == "report_summary"
)

print(
    "PASS - report summary exploitation accepted"
)


# TEST 10 - Correlated report title exploitation

result = calculate_priority(
    {
        "title": "Vendor security update",
        "evidence_reports": [
            {
                "title": (
                    "Vulnerability actively exploited "
                    "in attacks"
                ),
                "summary": "",
            },
        ],
        "nvd": [nvd(9.8)],
        "kev": [kev()],
        "iocs": {},
    }
)

assert result["level"] == "CRITICAL"
assert result["score"] == 65

assert (
    result["exploitation_evidence_source"]
    == "report_title"
)

print(
    "PASS - report title exploitation accepted"
)


print()
print("All priority tests passed.")