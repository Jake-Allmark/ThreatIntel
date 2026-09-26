import json
import os

from openai import OpenAI

from ai.grounding import ground_analysis


# Evidence-size controls.
MAX_REPORT_TEXT_CHARS = 12_000
MAX_REPORTS_PER_EVENT = 4
MAX_NVD_REFERENCES = 5


SYSTEM_PROMPT = """
You are a defensive cyber threat-intelligence analyst.

Analyse ONLY the evidence supplied by the application.

STRICT RULES:

1. Never invent facts.

2. Never invent affected products or versions.

3. Never invent CVEs, CVSS scores, CWE identifiers,
   exploitation status, threat actors, malware, victims,
   IOCs, customer impact, or mitigations.

4. If evidence is insufficient, return UNKNOWN.

5. Distinguish:
   FACT - directly supported by authoritative evidence.
   REPORTED - claimed by a supplied source.
   INFERENCE - a cautious analytical conclusion.
   UNKNOWN - evidence is insufficient.

6. Do not turn an inference into a fact.

7. Preserve contradictions between sources.

8. Recommendations must be defensive and justified by
   the supplied evidence.

9. Customer communication should only be recommended
   when evidence suggests possible customer exposure,
   compromise, service impact, required mitigation,
   or another concrete reason.

10. Confidence measures evidence quality, not severity.

11. Do not determine operational priority. The
    application calculates priority separately.

12. Absence of evidence is not evidence of absence.

13. Deterministic NVD and CISA KEV evidence must not be
    contradicted or silently changed.

14. Never promote a candidate IOC to a confirmed IOC
    unless the supplied evidence establishes that it is
    actually associated with the threat.

15. Source URLs and ordinary domains appearing in article
    text are not automatically indicators of compromise.

16. A CVE having no supplied CISA KEV match does not prove
    that the CVE is absent from CISA KEV.

17. Do not infer affected versions from product names,
    CVE numbering, dates, or general knowledge.

18. If sources disagree, record the disagreement in the
    contradictions field.

19. Evidence excerpts may be truncated. Do not interpret
    missing text as evidence that something did not occur.

Return valid JSON only.
"""


def get_client():
    api_key = os.getenv("OPENAI_API_KEY")

    if not api_key:
        raise RuntimeError(
            "OPENAI_API_KEY is not configured."
        )

    return OpenAI(api_key=api_key)


def get_model():
    model = os.getenv("OPENAI_MODEL")

    if not model:
        raise RuntimeError(
            "OPENAI_MODEL is not configured."
        )

    return model


def compact_nvd_record(record):
    """
    Remove large NVD structures that are not required
    for the AI narrative analysis.
    """

    if not isinstance(record, dict):
        return {}

    if record.get("error"):
        return {
            "cve": record.get("cve"),
            "error": record.get("error"),
        }

    references = []

    for reference in record.get(
        "references",
        [],
    )[:MAX_NVD_REFERENCES]:
        references.append(
            {
                "url": reference.get("url"),
                "source": reference.get("source"),
                "tags": reference.get("tags", []),
            }
        )

    return {
        "cve": record.get("cve"),
        "status": record.get("status"),
        "published": record.get("published"),
        "last_modified": record.get("last_modified"),
        "description": record.get("description", ""),
        "cvss": record.get("cvss"),
        "cwes": record.get("cwes", []),
        "references": references,
    }


def compact_kev_record(record):
    """
    Keep only operationally useful KEV fields.
    """

    return {
        "cve": record.get("cve"),
        "vendor": record.get("vendor"),
        "product": record.get("product"),
        "vulnerability_name": record.get(
            "vulnerability_name"
        ),
        "date_added": record.get("date_added"),
        "due_date": record.get("due_date"),
        "ransomware_use": record.get(
            "ransomware_use"
        ),
        "required_action": record.get(
            "required_action"
        ),
    }


def compact_sources(event):
    sources = []

    for source in event.get(
        "sources",
        [],
    )[:MAX_REPORTS_PER_EVENT]:
        sources.append(
            {
                "source": source.get(
                    "source",
                    "Unknown",
                ),
                "title": source.get(
                    "title",
                    "",
                ),
                "url": source.get(
                    "url",
                    "",
                ),
                "published_at": str(
                    source.get(
                        "published_at",
                        "",
                    )
                ),
            }
        )

    return sources


def compact_evidence_reports(event):
    reports = []

    for report in event.get(
        "evidence_reports",
        [],
    )[:MAX_REPORTS_PER_EVENT]:

        text = report.get(
            "evidence_text",
            "",
        )

        text = text[
            :MAX_REPORT_TEXT_CHARS
        ]

        reports.append(
            {
                "source": report.get(
                    "source",
                    "Unknown",
                ),
                "title": report.get(
                    "title",
                    "",
                ),
                "url": report.get(
                    "url",
                    "",
                ),
                "published_at": str(
                    report.get(
                        "published_at",
                        "",
                    )
                ),
                "evidence_excerpt": text,
                "cves": report.get(
                    "cves",
                    [],
                ),
                "candidate_iocs": report.get(
                    "iocs",
                    {},
                ),
            }
        )

    return reports


def build_evidence_package(event):
    """
    Produce a compact evidence package.

    Large NVD configuration trees and excessive
    references are deliberately excluded.
    """

    nvd = [
        compact_nvd_record(record)
        for record in event.get(
            "nvd",
            [],
        )
    ]

    kev = [
        compact_kev_record(record)
        for record in event.get(
            "kev",
            [],
        )
    ]

    priority = event.get(
        "priority",
        {},
    )

    correlation = event.get(
        "correlation",
        {},
    )

    return {
        "title": event.get(
            "title",
            "",
        ),
        "sources": compact_sources(
            event
        ),
        "evidence_reports":
            compact_evidence_reports(
                event
            ),
        "deterministic_cves": event.get(
            "cves",
            [],
        ),
        "nvd": nvd,
        "cisa_kev_matches": kev,
        "candidate_iocs": event.get(
            "iocs",
            {},
        ),
        "correlation": {
            "source_count": correlation.get(
                "source_count",
                1,
            ),
            "evidence_report_count":
                correlation.get(
                    "evidence_report_count",
                    1,
                ),
        },
        "application_priority": {
            "level": priority.get(
                "level",
                "INFORMATIONAL",
            ),
            "score": priority.get(
                "score",
                0,
            ),
            "reasons": priority.get(
                "reasons",
                [],
            ),
        },
    }


def build_user_prompt(event):
    evidence = build_evidence_package(
        event
    )

    requested_structure = {
        "title": "string",
        "event_type": (
            "vulnerability | malware | ransomware | "
            "breach | phishing | campaign | advisory | "
            "research | other"
        ),
        "executive_summary": "string",
        "what_is_it": "string",
        "affected_technologies": [
            {
                "technology": "string",
                "vendor": "string or UNKNOWN",
                "product": "string or UNKNOWN",
                "versions": [
                    "evidence-supported version"
                ],
                "evidence_status": (
                    "FACT | REPORTED | "
                    "INFERENCE | UNKNOWN"
                ),
            }
        ],
        "potential_impact": [
            {
                "impact": "string",
                "evidence_status": (
                    "FACT | REPORTED | "
                    "INFERENCE | UNKNOWN"
                ),
            }
        ],
        "exploitation": {
            "status": (
                "confirmed | reported | "
                "possible | unknown"
            ),
            "evidence": "string",
            "evidence_status": (
                "FACT | REPORTED | "
                "INFERENCE | UNKNOWN"
            ),
        },
        "vulnerabilities": [
            {
                "cve": "string",
                "cvss": "number or null",
                "cwe": ["string"],
                "cisa_kev": (
                    "true | false | null"
                ),
            }
        ],
        "threat_actors": ["string"],
        "malware": ["string"],
        "campaigns": ["string"],
        "iocs": {
            "ipv4": ["string"],
            "domains": ["string"],
            "urls": ["string"],
            "md5": ["string"],
            "sha1": ["string"],
            "sha256": ["string"],
        },
        "recommended_actions": [
            {
                "action": "string",
                "reason": "string",
                "category": (
                    "patch | mitigate | investigate | "
                    "hunt | block | monitor | "
                    "inform_internal | "
                    "consider_customer_communication"
                ),
            }
        ],
        "known_facts": ["string"],
        "reported_claims": ["string"],
        "working_hypotheses": ["string"],
        "intelligence_gaps": ["string"],
        "contradictions": ["string"],
        "confidence": (
            "high | medium | low"
        ),
        "confidence_reason": "string",
    }

    return (
        "Analyse this threat-intelligence evidence.\n\n"
        "Return JSON matching this structure.\n"
        "Do not add unsupported information.\n"
        "Candidate IOCs are NOT automatically "
        "confirmed IOCs.\n\n"
        + json.dumps(
            requested_structure,
            indent=2,
        )
        + "\n\nEVIDENCE:\n"
        + json.dumps(
            evidence,
            indent=2,
            default=str,
        )
    )


def clean_json_output(raw_output):
    raw_output = raw_output.strip()

    if raw_output.startswith(
        "```json"
    ):
        raw_output = raw_output[7:]

    elif raw_output.startswith(
        "```"
    ):
        raw_output = raw_output[3:]

    if raw_output.endswith(
        "```"
    ):
        raw_output = raw_output[:-3]

    return raw_output.strip()


def validate_analysis(analysis):
    if not isinstance(
        analysis,
        dict,
    ):
        raise RuntimeError(
            "AI analysis must be a JSON object."
        )

    required_fields = [
        "title",
        "event_type",
        "executive_summary",
        "what_is_it",
        "affected_technologies",
        "potential_impact",
        "exploitation",
        "vulnerabilities",
        "threat_actors",
        "malware",
        "campaigns",
        "iocs",
        "recommended_actions",
        "known_facts",
        "reported_claims",
        "working_hypotheses",
        "intelligence_gaps",
        "contradictions",
        "confidence",
        "confidence_reason",
    ]

    missing = [
        field
        for field in required_fields
        if field not in analysis
    ]

    if missing:
        raise RuntimeError(
            "AI response is missing required "
            "fields: "
            + ", ".join(missing)
        )

    confidence = str(
        analysis.get(
            "confidence",
            "",
        )
    ).lower()

    if confidence not in {
        "high",
        "medium",
        "low",
    }:
        raise RuntimeError(
            "AI returned invalid confidence: "
            + str(
                analysis.get(
                    "confidence"
                )
            )
        )

    return analysis


def analyse_event(event):
    """
    Analyse one event with Luna, validate its JSON,
    and then enforce deterministic grounding before
    returning the result to ThreatIntel.
    """

    client = get_client()
    model = get_model()

    response = client.responses.create(
        model=model,
        instructions=SYSTEM_PROMPT,
        input=build_user_prompt(
            event
        ),
    )

    raw_output = clean_json_output(
        response.output_text
    )

    try:
        analysis = json.loads(
            raw_output
        )

    except json.JSONDecodeError as error:
        raise RuntimeError(
            "AI returned invalid JSON: "
            f"{error}"
        ) from error

    analysis = validate_analysis(
        analysis
    )

    # IMPORTANT:
    # Never expose raw AI analysis directly.
    # Pass it through our deterministic grounding
    # boundary first.
    grounded = ground_analysis(
        event,
        analysis,
    )

    analysis = grounded[
        "analysis"
    ]

    grounding = grounded[
        "grounding"
    ]

    usage = getattr(
        response,
        "usage",
        None,
    )

    return {
        "analysis": analysis,
        "grounding": grounding,
        "usage": {
            "input_tokens": getattr(
                usage,
                "input_tokens",
                None,
            ),
            "output_tokens": getattr(
                usage,
                "output_tokens",
                None,
            ),
            "total_tokens": getattr(
                usage,
                "total_tokens",
                None,
            ),
        },
        "model": model,
    }