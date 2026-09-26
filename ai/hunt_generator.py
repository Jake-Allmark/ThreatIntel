import json
import re

from ai.client import get_client, get_model


REVIEW_STATUS = "REVIEW BEFORE DEPLOYMENT"
INSUFFICIENT = "INSUFFICIENT EVIDENCE FOR FOCUSED HUNT"


SYSTEM_PROMPT = f"""
You are a senior SOC threat hunter.

Convert the supplied evidence-grounded cyber threat event into one
practical SOC threat-hunting pack.

GROUNDING RULES

1. Use only the supplied threat evidence.
2. Never invent domains, IP addresses, hashes, URLs, filenames,
   process names, command lines, CVEs, threat actors, malware
   families, affected products, affected versions, exploitation
   status, or customer compromise.

3. You MAY generalize hunting logic from an explicitly supported
   behaviour.

4. Managed-estate relevance does not prove vulnerability,
   exploitation, or compromise.

5. Candidate IOCs are unverified unless the evidence establishes
   malicious association.

6. Every platform query is a hunting starting point and must be
   marked:

{REVIEW_STATUS}

FOCUSED-HUNT REQUIREMENT

A usable hunt query MUST contain at least one evidence-backed
discriminator, such as:

- a supported process or command behaviour
- a supported execution technique
- a supported file characteristic
- a supported network behaviour
- a supported identity behaviour
- a supplied, evidence-supported IOC pivot

A date/time range alone is NOT a hunt.

A query that merely returns all process, file, or network events is
NOT a hunt.

Do not use an intelligence-publication or campaign date window as the
primary scope of a reusable SOC hunt.

If the evidence does not support a focused query for a platform,
begin that platform's query field with exactly:

{INSUFFICIENT}

Then briefly explain why.

PLATFORM RULES

Google SecOps:
- Label: Google SecOps - UDM Hunt.
- Use normalized UDM hunting logic where supported.
- Do not describe it as a YARA hunt or YARA rule.
- Do not invent organization-specific parser mappings.
- State when UDM field population must be verified locally.

Microsoft Defender XDR:
- Label: Microsoft Defender XDR - KQL Advanced Hunting.
- Use relevant standard Advanced Hunting tables only.
- Do not invent tenant-specific tables or columns.

Cortex XDR:
- Label: Cortex XDR - XQL.
- Use conservative XQL.
- State when fields or datasets require local schema validation.
- Prefer insufficient evidence over guessed XQL fields.

Prefer behaviour-based hunting over brittle IOC-only matching.

Return valid JSON only.
Do not include Markdown code fences.
"""


def _clip(value, limit=8000):
    if value is None:
        return ""

    value = str(value)

    if len(value) <= limit:
        return value

    return value[:limit] + "\n[TRUNCATED]"


def _safe_list(value):
    if isinstance(value, list):
        return value

    return []


def build_hunt_evidence(event, hunt_selection):
    evidence = {
        "event_title": event.get("title"),

        "event_summary": _clip(
            event.get("summary", ""),
            5000,
        ),

        "priority": event.get(
            "priority",
            {},
        ),

        "relevance": event.get(
            "relevance",
            {},
        ),

        "managed_estate_relevance": event.get(
            "customer_asset_exposure",
            {},
        ),

        "cves": _safe_list(
            event.get("cves", [])
        ),

        "candidate_iocs": _safe_list(
            event.get("candidate_iocs", [])
        ),

        "hunt_selector": {
            "score": hunt_selection.get("score"),

            "behaviours": hunt_selection.get(
                "behaviours",
                [],
            ),

            "telemetry": hunt_selection.get(
                "telemetry",
                [],
            ),

            "reasons": hunt_selection.get(
                "reasons",
                [],
            ),

            "active_exploitation": hunt_selection.get(
                "active_exploitation",
                False,
            ),

            "managed_estate_relevant": hunt_selection.get(
                "managed_estate_relevant",
                False,
            ),
        },

        "source_reports": [],
    }

    reports = event.get(
        "evidence_reports",
        [],
    ) or []

    for report in reports[:4]:
        if not isinstance(report, dict):
            continue

        evidence["source_reports"].append(
            {
                "source": report.get("source"),

                "title": report.get("title"),

                "url": report.get("url"),

                "summary": _clip(
                    report.get("summary", ""),
                    3000,
                ),

                "article_text": _clip(
                    report.get("article_text", ""),
                    7000,
                ),
            }
        )

    return evidence


def build_user_prompt(evidence):
    schema = {
        "title": "string",

        "hypothesis": "string",

        "why_selected": [
            "string"
        ],

        "managed_estate_relevance": {
            "relevant": "boolean",

            "technologies": [
                "string"
            ],

            "assessment": "string",
        },

        "threat_characteristics": [
            "string"
        ],

        "attack_chain": [
            {
                "stage": "string",
                "activity": "string",
                "evidence_basis": "string",
            }
        ],

        "expected_telemetry": [
            "string"
        ],

        "google_secops_udm": {
            "status": REVIEW_STATUS,
            "query": "string",
            "what_it_looks_for": "string",
            "environment_notes": [
                "string"
            ],
        },

        "microsoft_defender_kql": {
            "status": REVIEW_STATUS,
            "query": "string",
            "what_it_looks_for": "string",
            "environment_notes": [
                "string"
            ],
        },

        "cortex_xdr_xql": {
            "status": REVIEW_STATUS,
            "query": "string",
            "what_it_looks_for": "string",
            "environment_notes": [
                "string"
            ],
        },

        "why_suspicious": [
            "string"
        ],

        "potential_false_positives": [
            "string"
        ],

        "analyst_validation": [
            "string"
        ],

        "intelligence_gaps": [
            "string"
        ],

        "source_intelligence": [
            {
                "source": "string",
                "title": "string",
                "url": "string",
            }
        ],

        "confidence": "HIGH | MEDIUM | LOW",

        "confidence_reason": "string",
    }

    return (
        "Create one practical SOC threat-hunting pack from "
        "the supplied evidence.\n\n"

        "Do not manufacture missing technical details.\n"

        "Do not turn a historical campaign date into the "
        "hunt itself.\n"

        "Each usable query needs an evidence-backed "
        "behavioural or IOC discriminator.\n"

        f"If that is impossible, begin the query with: "
        f"{INSUFFICIENT}\n\n"

        "The attack_chain must contain only "
        "evidence-supported stages.\n\n"

        "Return JSON matching this structure:\n"

        + json.dumps(
            schema,
            indent=2,
        )

        + "\n\nEVIDENCE:\n"

        + json.dumps(
            evidence,
            indent=2,
            ensure_ascii=False,
        )
    )


def _query_is_insufficient(query):
    return (
        str(query or "")
        .strip()
        .upper()
        .startswith(INSUFFICIENT)
    )


def _looks_date_only_or_generic(query):
    text = str(query or "").lower().strip()

    if not text:
        return True

    if _query_is_insufficient(query):
        return False

    generic_event_terms = (
        "process_launch",
        "file_creation",
        "network_connection",
        "deviceprocessevents",
        "devicenetworkevents",
        "devicefileevents",
    )

    behavioural_discriminators = (
        "powershell",
        "pwsh",
        "mshta",
        "rundll32",
        "regsvr32",
        "certutil",
        "bitsadmin",
        "psexec",
        "winrm",
        "wmic",
        "phish",
        "credential",
        "clipboard",
        "captcha",
        "injection",
        "hollow",
        "scheduled task",
        "remote desktop",
        "ransomware",
        "beacon",
        "command and control",
    )

    ioc_discriminators = (
        "sha256",
        "sha1",
        "md5",
    )

    has_generic_telemetry = any(
        term in text
        for term in generic_event_terms
    )

    has_behaviour = any(
        term in text
        for term in behavioural_discriminators
    )

    has_ioc = any(
        term in text
        for term in ioc_discriminators
    )

    has_date_filter = bool(
        re.search(
            r"\b20\d{2}-\d{2}-\d{2}",
            text,
        )
    )

    has_date_filter = (
        has_date_filter
        or "event_timestamp" in text
        or "starttime" in text
        or "endtime" in text
    )

    if (
        has_generic_telemetry
        and has_date_filter
        and not has_behaviour
        and not has_ioc
    ):
        return True

    return False


def validate_hunt_pack(pack):
    problems = []

    required = [
        "title",
        "hypothesis",
        "google_secops_udm",
        "microsoft_defender_kql",
        "cortex_xdr_xql",
        "potential_false_positives",
        "analyst_validation",
        "confidence",
    ]

    for field in required:
        if field not in pack:
            problems.append(
                f"Missing field: {field}"
            )

    query_sections = [
        "google_secops_udm",
        "microsoft_defender_kql",
        "cortex_xdr_xql",
    ]

    for section_name in query_sections:
        section = pack.get(
            section_name,
            {},
        )

        if not isinstance(
            section,
            dict,
        ):
            problems.append(
                f"{section_name} is not an object."
            )
            continue

        if (
            section.get("status")
            != REVIEW_STATUS
        ):
            problems.append(
                f"{section_name} is missing the "
                f"{REVIEW_STATUS} status."
            )

        query = section.get(
            "query",
            "",
        )

        if not query:
            problems.append(
                f"{section_name} has no query "
                "or explanatory fallback."
            )
            continue

        if _looks_date_only_or_generic(
            query
        ):
            problems.append(
                f"{section_name} is too broad: "
                "date/time plus generic telemetry "
                "is not a focused hunt."
            )

    return problems


def generate_hunt_pack(
    event,
    hunt_selection,
):
    evidence = build_hunt_evidence(
        event,
        hunt_selection,
    )

    prompt = build_user_prompt(
        evidence
    )

    client = get_client()
    model = get_model()

    response = client.responses.create(
        model=model,
        instructions=SYSTEM_PROMPT,
        input=prompt,
    )

    raw = response.output_text

    if not raw:
        raise RuntimeError(
            "OpenAI returned an empty hunt-pack response."
        )

    raw = raw.strip()

    if raw.startswith("```"):
        lines = raw.splitlines()

        if (
            lines
            and lines[0].startswith("```")
        ):
            lines = lines[1:]

        if (
            lines
            and lines[-1].strip() == "```"
        ):
            lines = lines[:-1]

        raw = "\n".join(
            lines
        ).strip()

    pack = json.loads(
        raw
    )

    if not isinstance(
        pack,
        dict,
    ):
        raise RuntimeError(
            "OpenAI hunt-pack response "
            "was not a JSON object."
        )

    problems = validate_hunt_pack(
        pack
    )

    pack["validation"] = {
        "passed": (
            len(problems) == 0
        ),

        "problems": problems,
    }

    return pack