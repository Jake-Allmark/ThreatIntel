from reporting.terminal import (
    show_ai_details,
    show_banner,
    show_event_table,
    show_run_summary,
)


events = [
    {
        "title": (
            "Actively exploited network management "
            "vulnerability observed in attacks"
        ),
        "source": "Security Research",
        "sources": [
            {
                "source": "Security Research",
            },
            {
                "source": "Vendor Advisory",
            },
        ],
        "priority": {
            "level": "CRITICAL",
            "score": 90,
        },
        "ai_status": "success",
        "ai_analysis": {
            "title": (
                "Network Management Platform "
                "Under Active Exploitation"
            ),
            "executive_summary": (
                "Multiple supplied sources report "
                "active exploitation affecting a "
                "network management platform. "
                "Defenders should identify exposed "
                "systems and review the applicable "
                "vendor mitigation guidance."
            ),
            "exploitation": {
                "status": "confirmed",
            },
            "confidence": "high",
        },
        "grounding": {
            "passed": True,
            "rejected_count": 0,
            "correction_count": 0,
        },
        "ai_usage": {
            "total_tokens": 4200,
        },
    },
    {
        "title": (
            "Enterprise gateway security update "
            "addresses critical vulnerability"
        ),
        "source": "Vendor Advisory",
        "sources": [],
        "priority": {
            "level": "HIGH",
            "score": 55,
        },
        "ai_status": "not_run",
    },
    {
        "title": (
            "New phishing campaign targets "
            "cloud account credentials"
        ),
        "source": "Threat Research",
        "sources": [],
        "priority": {
            "level": "MEDIUM",
            "score": 25,
        },
        "ai_status": "not_run",
    },
    {
        "title": (
            "Security researchers publish analysis "
            "of emerging malware techniques"
        ),
        "source": "Research Blog",
        "sources": [],
        "priority": {
            "level": "INFORMATIONAL",
            "score": 0,
        },
        "ai_status": "not_run",
    },
]


show_banner()

show_event_table(
    events
)

show_ai_details(
    events
)

show_run_summary(
    report_count=12,
    event_count=4,
    ai_count=1,
    failed_sources=[],
)