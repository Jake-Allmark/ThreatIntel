from collectors.article import fetch_article
from ai.client import analyse_event

from processing.extract import extract_intelligence
from processing.iocs import classify_iocs
from processing.kev import enrich_cves_with_kev
from processing.nvd import fetch_nvd_cve
from processing.score import calculate_priority
from processing.textclean import (
    clean_inline_text,
    clean_text,
)


def enrich_cves_with_nvd(cves):
    results = []

    for cve in cves:
        try:
            record = fetch_nvd_cve(
                cve
            )

            results.append(
                record
            )

        except Exception as error:
            #
            # NVD failure must not destroy
            # the intelligence event.
            #
            results.append(
                {
                    "cve": cve,
                    "error": str(error),
                }
            )

    return results


def process_item(
    item,
    kev_index,
):
    """
    Convert one collected source item into a
    deterministic intelligence record.

    AI is deliberately NOT called here.
    """

    try:
        #
        # Clean source-level fields immediately.
        #
        # This prevents RSS HTML, encoded entities,
        # malformed separators and similar feed
        # artefacts from propagating through:
        #
        # extraction
        # correlation
        # scoring
        # AI
        # JSON
        # PDF
        #
        source = clean_inline_text(
            item.get(
                "source",
                "Unknown",
            )
        )

        title = clean_inline_text(
            item.get(
                "title",
                "Untitled report",
            )
        )

        if not title:
            title = "Untitled report"

        url = str(
            item.get(
                "url",
                "",
            )
            or ""
        ).strip()

        summary = clean_text(
            item.get(
                "summary",
                "",
            )
        )

        #
        # Attempt full article retrieval.
        #
        article_text = ""

        try:
            article_text = fetch_article(
                url
            )

        except Exception:
            #
            # Article retrieval failure is not
            # fatal. RSS/API evidence remains.
            #
            article_text = ""

        #
        # Clean retrieved article text as well.
        #
        article_text = clean_text(
            article_text
        )

        #
        # Prefer full article evidence where it
        # was successfully retrieved.
        #
        evidence_text = (
            article_text
            if article_text
            else summary
        )

        evidence_text = clean_text(
            evidence_text
        )

        #
        # Include title + feed summary + evidence.
        #
        # CVEs and other useful evidence can appear
        # in any of these fields.
        #
        extraction_text = "\n\n".join(
            value
            for value in (
                title,
                summary,
                evidence_text,
            )
            if value
        )

        extraction_text = clean_text(
            extraction_text
        )

        extracted = (
            extract_intelligence(
                extraction_text
            )
        )

        cves = extracted.get(
            "cves",
            [],
        )

        #
        # Classify raw IOC-like values before they
        # enter the rest of the pipeline.
        #
        ioc_classification = (
            classify_iocs(
                extracted,
                source_url=url,
            )
        )

        candidate_iocs = (
            ioc_classification[
                "candidate"
            ]
        )

        kev_records = (
            enrich_cves_with_kev(
                cves,
                kev_index,
            )
        )

        nvd_records = (
            enrich_cves_with_nvd(
                cves
            )
        )

        record = {
            "source": (
                source
                or "Unknown"
            ),
            "title": title,
            "url": url,
            "published_at": item.get(
                "published_at"
            ),
            "summary": summary,
            "article_text": (
                article_text
            ),
            "evidence_text": (
                evidence_text
            ),

            #
            # Deterministic intelligence.
            #
            "cves": cves,

            #
            # From this point onward "iocs"
            # means candidate threat indicators,
            # not every URL/domain found in text.
            #
            "iocs": candidate_iocs,

            #
            # Retain the classification audit so
            # nothing is silently discarded.
            #
            "ioc_classification": (
                ioc_classification
            ),

            "kev": kev_records,
            "nvd": nvd_records,

            "correlation": {
                "matches": [],
                "source_count": 1,
                "evidence_report_count": 1,
            },

            #
            # AI fields.
            #
            "ai_analysis": None,
            "ai_status": "not_run",
            "ai_error": None,
            "ai_usage": None,
            "ai_model": None,
            "grounding": None,
        }

        #
        # Priority is calculated only after all
        # deterministic evidence has been built.
        #
        record["priority"] = (
            calculate_priority(
                record
            )
        )

        return record

    except Exception as error:
        #
        # One bad report must not terminate the
        # entire collection run.
        #
        # Clean the fallback fields too, because
        # processing-error records may still appear
        # in reports or diagnostics.
        #
        return {
            "source": (
                clean_inline_text(
                    item.get(
                        "source",
                        "Unknown",
                    )
                )
                or "Unknown"
            ),
            "title": (
                clean_inline_text(
                    item.get(
                        "title",
                        "Untitled report",
                    )
                )
                or "Untitled report"
            ),
            "url": str(
                item.get(
                    "url",
                    "",
                )
                or ""
            ).strip(),
            "published_at": item.get(
                "published_at"
            ),
            "processing_error": (
                str(error)
            ),
            "ai_analysis": None,
            "ai_status": "skipped",
            "ai_error": None,
            "ai_usage": None,
            "ai_model": None,
            "grounding": None,
        }


def process_items(
    items,
    kev_index,
    status_callback=None,
):
    results = []

    for item in items:
        record = process_item(
            item,
            kev_index,
        )

        results.append(
            record
        )

        if status_callback:
            status_callback(
                record
            )

    return results


def enrich_event_with_ai(
    event,
):
    """
    AI enrichment is isolated from deterministic
    processing so an API failure cannot destroy
    collected intelligence.
    """

    if (
        "processing_error"
        in event
    ):
        event[
            "ai_status"
        ] = "skipped"

        return event

    try:
        result = analyse_event(
            event
        )

        event[
            "ai_analysis"
        ] = result.get(
            "analysis"
        )

        event[
            "grounding"
        ] = result.get(
            "grounding"
        )

        event[
            "ai_usage"
        ] = result.get(
            "usage"
        )

        event[
            "ai_model"
        ] = result.get(
            "model"
        )

        event[
            "ai_status"
        ] = "success"

        event[
            "ai_error"
        ] = None

    except Exception as error:
        #
        # AI is enrichment, not a dependency for
        # retaining the underlying intelligence.
        #
        event[
            "ai_status"
        ] = "failed"

        event[
            "ai_error"
        ] = str(
            error
        )

    return event


def enrich_events_with_ai(
    events,
    status_callback=None,
):
    results = []

    for event in events:
        result = enrich_event_with_ai(
            event
        )

        results.append(
            result
        )

        if status_callback:
            status_callback(
                result
            )

    return results