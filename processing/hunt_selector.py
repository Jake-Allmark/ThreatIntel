import re


MAX_HUNTS = 3


# Huntability is intentionally independent from event priority.
#
# These patterns represent observable behaviour that an analyst may
# reasonably be able to search for in endpoint, identity, email or
# network telemetry.
BEHAVIOUR_RULES = {
    "powershell": {
        "weight": 22,
        "patterns": [
            r"\bpowershell\b",
            r"\bpwsh\b",
            r"\bpowershell\.exe\b",
        ],
        "telemetry": [
            "process",
            "command_line",
        ],
    },

    "script_execution": {
        "weight": 16,
        "patterns": [
            r"\bjavascript\b",
            r"\bjscript\b",
            r"\bvbscript\b",
            r"\bwscript\b",
            r"\bcscript\b",
            r"\bhta\b",
            r"\bmshta\b",
            r"\bbatch script\b",
            r"\bshell script\b",
        ],
        "telemetry": [
            "process",
            "command_line",
            "file",
        ],
    },

    "clickfix": {
        "weight": 24,
        "patterns": [
            r"\bclickfix\b",
            r"\bfake captcha\b",
            r"\bfake verification\b",
            r"\bclipboard\b.*\bcommand\b",
            r"\bcopy\b.*\bpowershell\b",
        ],
        "telemetry": [
            "process",
            "command_line",
            "web",
        ],
    },

    "phishing": {
        "weight": 18,
        "patterns": [
            r"\bphishing\b",
            r"\bspearphishing\b",
            r"\bspear phishing\b",
            r"\bcredential phishing\b",
            r"\bmalicious email\b",
        ],
        "telemetry": [
            "email",
            "web",
            "identity",
        ],
    },

    "credential_theft": {
        "weight": 22,
        "patterns": [
            r"\bcredential theft\b",
            r"\bcredential stealer\b",
            r"\bcredential stealing\b",
            r"\bsteal(?:s|ing)? credentials\b",
            r"\bpassword stealer\b",
            r"\binfostealer\b",
            r"\binfo stealer\b",
            r"\bsession cookie\b",
            r"\bauthentication cookie\b",
            r"\btoken theft\b",
        ],
        "telemetry": [
            "process",
            "identity",
            "file",
            "network",
        ],
    },

    "process_injection": {
        "weight": 24,
        "patterns": [
            r"\bprocess injection\b",
            r"\bdll injection\b",
            r"\bremote thread\b",
            r"\bprocess hollowing\b",
            r"\breflective loading\b",
            r"\breflective dll\b",
        ],
        "telemetry": [
            "process",
            "endpoint",
        ],
    },

    "malware_execution": {
        "weight": 18,
        "patterns": [
            r"\bmalware\b",
            r"\bransomware\b",
            r"\btrojan\b",
            r"\bbackdoor\b",
            r"\bloader\b",
            r"\bpayload\b",
            r"\bdropper\b",
            r"\bimplant\b",
            r"\bstealer\b",
        ],
        "telemetry": [
            "process",
            "file",
            "network",
        ],
    },

    "command_and_control": {
        "weight": 22,
        "patterns": [
            r"\bcommand and control\b",
            r"\bcommand-and-control\b",
            r"\bc2\b",
            r"\bc&c\b",
            r"\bbeacon(?:ing)?\b",
            r"\bcallback\b",
        ],
        "telemetry": [
            "network",
            "dns",
            "proxy",
            "endpoint",
        ],
    },

    "persistence": {
        "weight": 18,
        "patterns": [
            r"\bpersistence\b",
            r"\bscheduled task\b",
            r"\brun key\b",
            r"\bstartup folder\b",
            r"\bregistry run\b",
            r"\bservice creation\b",
            r"\bnew service\b",
        ],
        "telemetry": [
            "process",
            "registry",
            "endpoint",
        ],
    },

    "lateral_movement": {
        "weight": 20,
        "patterns": [
            r"\blateral movement\b",
            r"\bremote service\b",
            r"\bremote desktop\b",
            r"\brdp\b",
            r"\bpsexec\b",
            r"\bwinrm\b",
            r"\bwmi\b",
        ],
        "telemetry": [
            "process",
            "authentication",
            "network",
        ],
    },

    "remote_access": {
        "weight": 16,
        "patterns": [
            r"\bremote access tool\b",
            r"\bremote access software\b",
            r"\brat\b",
            r"\bremote monitoring\b",
            r"\bremote management tool\b",
        ],
        "telemetry": [
            "process",
            "network",
            "endpoint",
        ],
    },

    "living_off_the_land": {
        "weight": 20,
        "patterns": [
            r"\bliving off the land\b",
            r"\blolbin\b",
            r"\brundll32\b",
            r"\bregsvr32\b",
            r"\bcertutil\b",
            r"\bbitsadmin\b",
            r"\bwmic\b",
        ],
        "telemetry": [
            "process",
            "command_line",
            "network",
        ],
    },

    "suspicious_download": {
        "weight": 15,
        "patterns": [
            r"\bdownload(?:s|ed|ing)?\b.*\bpayload\b",
            r"\bdownload(?:s|ed|ing)?\b.*\bmalware\b",
            r"\bmalicious download\b",
            r"\bdownload cradle\b",
        ],
        "telemetry": [
            "process",
            "network",
            "web",
            "file",
        ],
    },

    "account_abuse": {
        "weight": 17,
        "patterns": [
            r"\baccount takeover\b",
            r"\bcompromised account\b",
            r"\bstolen account\b",
            r"\bvalid accounts\b",
            r"\bunauthorized login\b",
        ],
        "telemetry": [
            "identity",
            "authentication",
        ],
    },
}


PATCH_ONLY_PATTERNS = [
    r"\bapply (?:the )?patch\b",
    r"\binstall (?:the )?patch\b",
    r"\bupdate immediately\b",
    r"\bsecurity update\b",
    r"\bupgrade to\b",
    r"\baffected versions\b",
    r"\bpatch available\b",
]


PRIORITY_BONUS = {
    "CRITICAL": 12,
    "HIGH": 9,
    "MEDIUM": 6,
    "INFORMATIONAL": 0,
    "WATCHLIST": 0,
}


def normalize_text(value):
    if value is None:
        return ""

    return re.sub(
        r"\s+",
        " ",
        str(value),
    ).strip()


def collect_hunt_text(event):
    """
    Build text used only to decide whether an event contains
    huntable behaviour.

    Source reporting is preferred. AI output is deliberately not
    required for selection.
    """

    values = []

    for field in (
        "title",
        "summary",
        "evidence_text",
    ):
        value = event.get(field)

        if value:
            values.append(
                normalize_text(value)
            )

    for report in (
        event.get(
            "evidence_reports",
            [],
        )
        or []
    ):
        if not isinstance(
            report,
            dict,
        ):
            continue

        for field in (
            "title",
            "summary",
            "article_text",
        ):
            value = report.get(field)

            if value:
                values.append(
                    normalize_text(value)
                )

    return "\n".join(values)


def detect_behaviours(text):
    text_lower = text.lower()

    results = []

    for name, rule in (
        BEHAVIOUR_RULES.items()
    ):
        matched_patterns = []

        for pattern in rule[
            "patterns"
        ]:
            if re.search(
                pattern,
                text_lower,
                flags=re.IGNORECASE,
            ):
                matched_patterns.append(
                    pattern
                )

        if not matched_patterns:
            continue

        results.append(
            {
                "name": name,
                "weight": rule[
                    "weight"
                ],
                "telemetry": list(
                    rule["telemetry"]
                ),
                "matched_pattern_count": (
                    len(
                        matched_patterns
                    )
                ),
            }
        )

    return results


def get_candidate_iocs(event):
    """
    Candidate IOCs are supporting evidence only.

    Their presence does not mean they are malicious.
    """

    candidates = []

    ioc_data = (
        event.get(
            "ioc_classification",
            {},
        )
        or {}
    )

    if isinstance(
        ioc_data,
        dict,
    ):
        raw = (
            ioc_data.get(
                "candidate",
                [],
            )
            or []
        )

        if isinstance(
            raw,
            list,
        ):
            candidates.extend(raw)

    # Some report versions expose candidate IOCs directly.
    raw_direct = (
        event.get(
            "candidate_iocs",
            [],
        )
        or []
    )

    if isinstance(
        raw_direct,
        list,
    ):
        candidates.extend(
            raw_direct
        )

    return candidates


def customer_relevant(event):
    exposure = (
        event.get(
            "customer_asset_exposure",
            {},
        )
        or {}
    )

    return bool(
        exposure.get(
            "relevant",
            False,
        )
    )


def active_exploitation(event):
    priority = (
        event.get(
            "priority",
            {},
        )
        or {}
    )

    return bool(
        priority.get(
            "active_exploitation_language",
            False,
        )
    )


def event_priority(event):
    priority = (
        event.get(
            "priority",
            {},
        )
        or {}
    )

    return str(
        priority.get(
            "level",
            "INFORMATIONAL",
        )
    ).upper()


def source_count(event):
    sources = (
        event.get(
            "sources",
            [],
        )
        or []
    )

    if isinstance(
        sources,
        list,
    ):
        return len(
            {
                str(source)
                for source in sources
                if source
            }
        )

    return 0


def patch_only_penalty(
    text,
    behaviours,
):
    """
    Patch/advisory language is penalised only when there is little
    observable attack behaviour.

    A real exploited vulnerability can still become hunt-worthy if
    the reporting describes useful attacker behaviour.
    """

    if len(behaviours) >= 2:
        return 0

    matches = 0

    for pattern in (
        PATCH_ONLY_PATTERNS
    ):
        if re.search(
            pattern,
            text,
            flags=re.IGNORECASE,
        ):
            matches += 1

    if matches >= 2:
        return 20

    if matches == 1:
        return 10

    return 0


def score_huntability(event):
    text = collect_hunt_text(
        event
    )

    behaviours = detect_behaviours(
        text
    )

    score = sum(
        item["weight"]
        for item in behaviours
    )

    reasons = []

    if behaviours:
        reasons.append(
            "Observable attacker behaviour "
            "was identified."
        )

    if customer_relevant(event):
        score += 10

        reasons.append(
            "Relevant to the managed "
            "technology estate."
        )

    if active_exploitation(event):
        score += 8

        reasons.append(
            "Current exploitation evidence "
            "is present."
        )

    priority = event_priority(
        event
    )

    score += PRIORITY_BONUS.get(
        priority,
        0,
    )

    if priority in {
        "CRITICAL",
        "HIGH",
        "MEDIUM",
    }:
        reasons.append(
            f"{priority} operational priority."
        )

    candidates = get_candidate_iocs(
        event
    )

    if candidates:
        # Supporting signal only. Deliberately capped.
        score += min(
            len(candidates),
            5,
        )

        reasons.append(
            "Candidate indicators are "
            "available for analyst validation."
        )

    reports = source_count(
        event
    )

    if reports >= 2:
        score += min(
            reports,
            4,
        )

        reasons.append(
            "Multiple source references "
            "support the event."
        )

    penalty = patch_only_penalty(
        text,
        behaviours,
    )

    score -= penalty

    if penalty:
        reasons.append(
            "Reduced because the reporting "
            "is primarily patch/advisory oriented."
        )

    telemetry = sorted(
        {
            telemetry_type
            for behaviour in behaviours
            for telemetry_type in (
                behaviour.get(
                    "telemetry",
                    [],
                )
            )
        }
    )

    # At least one meaningful behaviour is required. Priority,
    # customer relevance or IOCs alone cannot make an event huntable.
    huntable = bool(
        behaviours
        and score >= 18
    )

    return {
        "huntable": huntable,
        "score": max(
            score,
            0,
        ),
        "behaviours": behaviours,
        "telemetry": telemetry,
        "reasons": reasons,
        "candidate_ioc_count": len(
            candidates
        ),
        "managed_estate_relevant": (
            customer_relevant(event)
        ),
        "active_exploitation": (
            active_exploitation(event)
        ),
        "priority": priority,
    }


def behaviour_names(result):
    return {
        item.get("name")
        for item in (
            result.get(
                "behaviours",
                [],
            )
            or []
        )
        if item.get("name")
    }


def too_similar(
    candidate_result,
    selected_results,
):
    """
    Avoid filling the report with essentially the same hunt.

    A candidate is considered too similar only when its behaviour
    set is completely covered by an already-selected hunt.
    """

    candidate = behaviour_names(
        candidate_result
    )

    if not candidate:
        return True

    for selected in selected_results:
        existing = behaviour_names(
            selected
        )

        if (
            candidate
            and candidate.issubset(
                existing
            )
        ):
            return True

    return False


def select_hunts(
    events,
    max_hunts=MAX_HUNTS,
):
    """
    Select 0..max_hunts THREAT events.

    We intentionally do not force the requested number. If only one
    event has sufficient observable behaviour, only one is returned.
    """

    candidates = []

    for event in events:
        relevance = (
            event.get(
                "relevance",
                {},
            )
            or {}
        )

        if (
            relevance.get(
                "classification"
            )
            != "THREAT"
        ):
            continue

        result = score_huntability(
            event
        )

        if not result[
            "huntable"
        ]:
            continue

        candidates.append(
            {
                "event": event,
                "hunt_selection": result,
            }
        )

    candidates.sort(
        key=lambda item: (
            item[
                "hunt_selection"
            ][
                "managed_estate_relevant"
            ],
            item[
                "hunt_selection"
            ][
                "score"
            ],
        ),
        reverse=True,
    )

    selected = []
    selected_results = []

    for candidate in candidates:
        if len(selected) >= max_hunts:
            break

        result = candidate[
            "hunt_selection"
        ]

        if too_similar(
            result,
            selected_results,
        ):
            continue

        selected.append(
            candidate
        )

        selected_results.append(
            result
        )

    return selected