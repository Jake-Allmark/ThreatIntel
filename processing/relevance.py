import re


# ============================================================
# OPERATIONAL THREAT SIGNALS
# ============================================================

THREAT_PATTERNS = {
    "cve": (
        r"\bCVE-\d{4}-\d{4,}\b"
    ),

    "zero_day": (
        r"\bzero[- ]day\b"
    ),

    "exploitation": (
        r"\b(?:"
        r"actively exploit|"
        r"actively exploits|"
        r"actively exploited|"
        r"actively exploiting|"
        r"active exploitation|"
        r"exploited in the wild|"
        r"exploitation in the wild|"
        r"exploited in attacks|"
        r"being exploited|"
        r"attackers exploit|"
        r"attackers exploiting|"
        r"hackers exploit|"
        r"hackers exploiting|"
        r"threat actors exploit|"
        r"threat actors exploiting|"
        r"observed exploitation|"
        r"confirmed exploitation"
        r")\b"
    ),

    "ransomware": (
        r"\bransomware\b"
    ),

    "malware": (
        r"\bmalware\b"
    ),

    "phishing": (
        r"\bphishing\b"
    ),

    "breach": (
        r"\b(?:data )?"
        r"breach(?:ed|es)?\b"
    ),

    "compromise": (
        r"\bcompromis"
        r"(?:e|ed|es|ing)\b"
    ),

    "credential_theft": (
        r"\b(?:"
        r"credential stealer|"
        r"credential theft|"
        r"stolen credentials|"
        r"password stealer|"
        r"infostealer"
        r")\b"
    ),

    "remote_code_execution": (
        r"\b(?:"
        r"remote code execution|"
        r"server code execution|"
        r"code execution|"
        r"RCE"
        r")\b"
    ),

    "privilege_escalation": (
        r"\b(?:"
        r"privilege escalation|"
        r"elevation of privilege|"
        r"run code as root|"
        r"execute code as root|"
        r"gain root access"
        r")\b"
    ),

    "unauthorized_access": (
        r"\b(?:"
        r"unauthorized access|"
        r"unauthenticated access|"
        r"authentication bypass|"
        r"without authentication|"
        r"without a password|"
        r"take full server control"
        r")\b"
    ),

    "command_and_control": (
        r"\b(?:"
        r"command and control|"
        r"command-and-control|"
        r"C2"
        r")\b"
    ),

    "malicious": (
        r"\bmalicious\b"
    ),

    "supply_chain": (
        r"\bsupply[- ]chain "
        r"(?:"
        r"attack|"
        r"attacks|"
        r"compromise|"
        r"compromised|"
        r"incident|"
        r"incidents"
        r")\b"
    ),

    "backdoor": (
        r"\bbackdoor\b"
    ),

    "botnet": (
        r"\bbotnet\b"
    ),

    "rootkit": (
        r"\brootkit\b"
    ),

    "spyware": (
        r"\bspyware\b"
    ),

    "trojan": (
        r"\btrojan\b"
    ),

    "worm": (
        r"\bcomputer worm\b"
    ),

    "web_skimmer": (
        r"\b(?:"
        r"web skimmer|"
        r"skimmer malware"
        r")\b"
    ),

    "clickfix": (
        r"\bclickfix\b"
    ),

    "edr_evasion": (
        r"\b(?:"
        r"EDR evasion|"
        r"disable(?:s|d|ing)? EDR|"
        r"bypass(?:es|ed|ing)? EDR"
        r")\b"
    ),

    "vulnerability": (
        r"\b(?:"
        r"vulnerability|"
        r"vulnerabilities"
        r")\b"
    ),

    "security_flaw": (
        r"\b(?:"
        r"security flaw|"
        r"critical flaw|"
        r"critical .* flaw"
        r")\b"
    ),

    "takeover": (
        r"\b(?:"
        r"account takeover|"
        r"server takeover|"
        r"take over .* server|"
        r"hand over .* organization"
        r")\b"
    ),

    "unauthorized_code_path": (
        r"\b(?:"
        r"push code|"
        r"run CI jobs|"
        r"execute arbitrary code|"
        r"arbitrary code execution"
        r")\b"
    ),
}


# ============================================================
# SECURITY CONTEXT SIGNALS
# ============================================================

CONTEXT_PATTERNS = {
    "threat_research": (
        r"\b(?:"
        r"threat research|"
        r"security research|"
        r"threat intelligence|"
        r"threat landscape"
        r")\b"
    ),

    "law_enforcement": (
        r"\b(?:"
        r"arrested|"
        r"arrest|"
        r"sentenced|"
        r"sentence|"
        r"indicted|"
        r"indictment|"
        r"extradited|"
        r"convicted|"
        r"conviction|"
        r"prison|"
        r"jail|"
        r"seized|"
        r"law enforcement"
        r")\b"
    ),

    "policy": (
        r"\b(?:"
        r"regulation|"
        r"regulatory|"
        r"legislation|"
        r"cybersecurity policy|"
        r"government policy"
        r")\b"
    ),

    "industry_analysis": (
        r"\b(?:"
        r"industry analysis|"
        r"security trends|"
        r"cyber trends|"
        r"threat trends"
        r")\b"
    ),
}


# ============================================================
# CLEAR NON-THREAT SIGNALS
# ============================================================

NON_THREAT_PATTERNS = {
    "webinar": (
        r"\b(?:"
        r"webinar|"
        r"webcast|"
        r"virtual event|"
        r"register now|"
        r"join us"
        r")\b"
    ),

    "conference": (
        r"\b(?:"
        r"conference|"
        r"summit|"
        r"workshop"
        r")\b"
    ),

    "funding": (
        r"\b(?:"
        r"raises|"
        r"raised|"
        r"funding round|"
        r"series [a-z] funding|"
        r"venture funding|"
        r"investment round"
        r")\b"
    ),

    "marketing": (
        r"\b(?:"
        r"product launch|"
        r"announces new platform|"
        r"introduces new platform|"
        r"customer success story|"
        r"partner program"
        r")\b"
    ),

    "survey": (
        r"\b(?:"
        r"survey finds|"
        r"survey reveals|"
        r"survey shows|"
        r"new survey|"
        r"research survey"
        r")\b"
    ),

    "award": (
        r"\b(?:"
        r"wins award|"
        r"named a leader|"
        r"recognized as a leader|"
        r"industry award"
        r")\b"
    ),

    "security_testing_methodology": (
        r"\b(?:"
        r"dynamic application security testing|"
        r"static application security testing|"
        r"application security testing|"
        r"penetration testing methodology|"
        r"security testing methodology"
        r")\b"
    ),
}


# ============================================================
# EVENT-INTENT OVERRIDES
# ============================================================

LAW_ENFORCEMENT_EVENT_PATTERN = (
    r"\b(?:"
    r"sentenced|"
    r"sentence|"
    r"arrested|"
    r"arrest|"
    r"indicted|"
    r"indictment|"
    r"extradited|"
    r"convicted|"
    r"conviction|"
    r"prison|"
    r"jail"
    r")\b"
)


ACTIVE_INCIDENT_PATTERN = (
    r"\b(?:"
    r"attack|"
    r"attacks|"
    r"attacked|"
    r"breach|"
    r"breached|"
    r"compromise|"
    r"compromised|"
    r"infect|"
    r"infected|"
    r"target|"
    r"targets|"
    r"targeting|"
    r"exploit|"
    r"exploits|"
    r"exploited|"
    r"exploiting"
    r")\b"
)


NON_THREAT_TITLE_PATTERNS = {
    "security_testing_methodology": (
        r"\b(?:"
        r"dynamic application security testing|"
        r"static application security testing|"
        r"application security testing|"
        r"penetration testing methodology|"
        r"security testing methodology"
        r")\b"
    ),
}


def normalize(value):
    return re.sub(
        r"\s+",
        " ",
        str(value or ""),
    ).strip()


def build_relevance_text(event):
    """
    Build relevance evidence from event/report titles and
    summaries only.

    Full article bodies are deliberately excluded because
    historical references, related links and navigation can
    create false operational threat signals.
    """

    parts = [
        event.get(
            "title",
            "",
        ),
        event.get(
            "summary",
            "",
        ),
    ]

    for report in event.get(
        "evidence_reports",
        [],
    ):
        parts.append(
            report.get(
                "title",
                "",
            )
        )

        parts.append(
            report.get(
                "summary",
                "",
            )
        )

    return normalize(
        " ".join(
            str(part or "")
            for part in parts
        )
    )


def find_matches(
    text,
    patterns,
):
    matches = []

    for name, pattern in patterns.items():
        if re.search(
            pattern,
            text,
            flags=re.IGNORECASE,
        ):
            matches.append(
                name
            )

    return matches


def has_deterministic_threat_evidence(
    event,
):
    """
    Structured threat evidence always has higher confidence
    than content-intent heuristics.
    """

    cves = event.get(
        "cves",
        [],
    ) or []

    kev = event.get(
        "kev",
        [],
    ) or []

    if cves:
        return True

    if kev:
        return True

    priority = event.get(
        "priority",
        {},
    ) or {}

    if priority.get(
        "active_exploitation_language"
    ):
        return True

    return False


def is_law_enforcement_event(
    event,
):
    title = normalize(
        event.get(
            "title",
            "",
        )
    )

    return bool(
        re.search(
            LAW_ENFORCEMENT_EVENT_PATTERN,
            title,
            flags=re.IGNORECASE,
        )
    )


def has_active_incident_language(
    event,
):
    title = normalize(
        event.get(
            "title",
            "",
        )
    )

    return bool(
        re.search(
            ACTIVE_INCIDENT_PATTERN,
            title,
            flags=re.IGNORECASE,
        )
    )


def get_non_threat_title_matches(
    event,
):
    """
    Some content types are clearly educational/promotional
    based on their primary title.

    We use the primary title for this override so generic
    vulnerability terminology in a summary does not turn an
    educational article into an operational threat.
    """

    title = normalize(
        event.get(
            "title",
            "",
        )
    )

    return find_matches(
        title,
        NON_THREAT_TITLE_PATTERNS,
    )


def classify_relevance(event):
    """
    Classify a correlated intelligence event as:

        THREAT
        CONTEXT
        NON_THREAT

    The classification controls presentation and AI
    eligibility. It never deletes the intelligence record.
    """

    text = build_relevance_text(
        event
    )

    threat_matches = find_matches(
        text,
        THREAT_PATTERNS,
    )

    context_matches = find_matches(
        text,
        CONTEXT_PATTERNS,
    )

    non_threat_matches = find_matches(
        text,
        NON_THREAT_PATTERNS,
    )

    non_threat_title_matches = (
        get_non_threat_title_matches(
            event
        )
    )

    deterministic_threat = (
        has_deterministic_threat_evidence(
            event
        )
    )

    law_enforcement_event = (
        is_law_enforcement_event(
            event
        )
    )

    active_incident = (
        has_active_incident_language(
            event
        )
    )

    #
    # 1. Structured CVE / KEV / confirmed exploitation
    # evidence has the strongest precedence.
    #
    if deterministic_threat:
        return {
            "classification": "THREAT",
            "reason": (
                "deterministic_threat_evidence"
            ),
            "threat_signals": (
                threat_matches
            ),
            "context_signals": (
                context_matches
            ),
            "non_threat_signals": (
                non_threat_matches
            ),
        }

    #
    # 2. Explicit educational/testing methodology titles
    # override generic security terminology found in their
    # summaries.
    #
    if non_threat_title_matches:
        combined_non_threat = list(
            dict.fromkeys(
                non_threat_matches
                + non_threat_title_matches
            )
        )

        return {
            "classification": "NON_THREAT",
            "reason": (
                "non_threat_content_intent"
            ),
            "threat_signals": (
                threat_matches
            ),
            "context_signals": (
                context_matches
            ),
            "non_threat_signals": (
                combined_non_threat
            ),
        }

    #
    # 3. Judicial/law-enforcement reporting about a threat
    # actor is context unless the primary title also describes
    # an active incident.
    #
    if (
        law_enforcement_event
        and not active_incident
    ):
        return {
            "classification": "CONTEXT",
            "reason": (
                "law_enforcement_event"
            ),
            "threat_signals": (
                threat_matches
            ),
            "context_signals": (
                context_matches
            ),
            "non_threat_signals": (
                non_threat_matches
            ),
        }

    #
    # 4. Explicit operational threat language.
    #
    if threat_matches:
        return {
            "classification": "THREAT",
            "reason": (
                "threat_language"
            ),
            "threat_signals": (
                threat_matches
            ),
            "context_signals": (
                context_matches
            ),
            "non_threat_signals": (
                non_threat_matches
            ),
        }

    #
    # 5. Promotional/event/funding material.
    #
    if non_threat_matches:
        return {
            "classification": "NON_THREAT",
            "reason": (
                "non_threat_content"
            ),
            "threat_signals": [],
            "context_signals": (
                context_matches
            ),
            "non_threat_signals": (
                non_threat_matches
            ),
        }

    #
    # 6. Useful cybersecurity context without sufficient
    # operational threat evidence.
    #
    if context_matches:
        return {
            "classification": "CONTEXT",
            "reason": (
                "security_context"
            ),
            "threat_signals": [],
            "context_signals": (
                context_matches
            ),
            "non_threat_signals": [],
        }

    #
    # 7. Unknown material remains available for analyst
    # review rather than being silently discarded.
    #
    return {
        "classification": "CONTEXT",
        "reason": (
            "insufficient_operational_threat_evidence"
        ),
        "threat_signals": [],
        "context_signals": [],
        "non_threat_signals": [],
    }


def apply_relevance(event):
    event[
        "relevance"
    ] = classify_relevance(
        event
    )

    return event


def apply_relevance_to_events(events):
    for event in events:
        if (
            "processing_error"
            in event
        ):
            event["relevance"] = {
                "classification": "CONTEXT",
                "reason": "processing_error",
                "threat_signals": [],
                "context_signals": [],
                "non_threat_signals": [],
            }

            continue

        apply_relevance(
            event
        )

    return events