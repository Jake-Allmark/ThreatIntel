import processing.process as processor


def fake_ai_failure(event):
    """
    Simulate an OpenAI outage, timeout,
    quota problem, or other API failure.
    """

    raise RuntimeError(
        "Simulated AI service failure"
    )


def main():
    event = {
        "source": "Test Source",
        "title": "Test Threat Event",
        "url": "https://example.invalid/test",
        "published_at": None,
        "summary": "Synthetic test event.",
        "article_text": "",
        "evidence_text": (
            "Synthetic threat evidence."
        ),
        "cves": [
            "CVE-2026-12345"
        ],
        "iocs": {
            "ipv4": [],
            "domains": [],
            "urls": [],
            "md5": [],
            "sha1": [],
            "sha256": [],
        },
        "kev": [],
        "nvd": [],
        "correlation": {},
        "priority": {
            "level": "HIGH",
            "score": 40,
            "reasons": [
                "Synthetic test"
            ],
        },
        "ai_analysis": None,
        "ai_status": "not_run",
        "ai_error": None,
        "ai_usage": None,
        "ai_model": None,
        "grounding": None,
    }

    # Temporarily replace the real AI function.
    original_analyse_event = (
        processor.analyse_event
    )

    processor.analyse_event = (
        fake_ai_failure
    )

    try:
        result = (
            processor.enrich_event_with_ai(
                event
            )
        )

    finally:
        # Always restore the real function.
        processor.analyse_event = (
            original_analyse_event
        )

    print(
        "TITLE:",
        result["title"],
    )

    print(
        "PRIORITY:",
        result["priority"]["level"],
    )

    print(
        "AI STATUS:",
        result["ai_status"],
    )

    print(
        "AI ERROR:",
        result["ai_error"],
    )

    print(
        "EVENT SURVIVED:",
        result["title"]
        == "Test Threat Event",
    )

    assert (
        result["ai_status"]
        == "failed"
    )

    assert (
        result["ai_analysis"]
        is None
    )

    assert (
        result["title"]
        == "Test Threat Event"
    )

    assert (
        result["priority"]["level"]
        == "HIGH"
    )

    print(
        "\nPASS: AI failure did not "
        "destroy the threat event."
    )


if __name__ == "__main__":
    main()