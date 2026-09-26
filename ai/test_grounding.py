import json

from ai.grounding import ground_analysis


event = {
    "cves": [
        "CVE-2026-12345",
    ],
    "nvd": [
        {
            "cve": "CVE-2026-12345",
        }
    ],
    "kev": [],
    "iocs": {
        "ipv4": [
            "192.0.2.10",
        ],
        "domains": [
            "example-malware.invalid",
        ],
        "urls": [],
        "md5": [],
        "sha1": [],
        "sha256": [],
    },
    "evidence_reports": [
        {
            "cves": [
                "CVE-2026-12345",
            ],
            "iocs": {
                "ipv4": [
                    "192.0.2.10",
                ],
                "domains": [
                    "example-malware.invalid",
                ],
                "urls": [],
                "md5": [],
                "sha1": [],
                "sha256": [],
            },
        }
    ],
}


fake_ai_analysis = {
    "vulnerabilities": [
        {
            "cve": "CVE-2026-12345",
            "cvss": 9.8,
            "cwe": [
                "CWE-999",
            ],
            "cisa_kev": True,
        },
        {
            "cve": "CVE-2099-99999",
            "cvss": 10.0,
            "cwe": [],
            "cisa_kev": True,
        },
    ],
    "iocs": {
        "ipv4": [
            "192.0.2.10",
            "203.0.113.250",
        ],
        "domains": [
            "example-malware.invalid",
            "hallucinated-domain.invalid",
        ],
        "urls": [],
        "md5": [],
        "sha1": [],
        "sha256": [],
    },
}


result = ground_analysis(
    event,
    fake_ai_analysis,
)


print(
    json.dumps(
        result,
        indent=2,
    )
)