def normalize(value):
    """
    Normalize a value for safe comparison.
    """

    if value is None:
        return ""

    return str(value).strip().lower()


def collect_allowed_cves(event):
    """
    Build the authoritative set of CVEs observed
    by the application.
    """

    allowed = set()

    for cve in event.get("cves", []):
        if cve:
            allowed.add(
                str(cve).upper()
            )

    for record in event.get("nvd", []):
        cve = record.get("cve")

        if cve:
            allowed.add(
                str(cve).upper()
            )

    for record in event.get("kev", []):
        cve = record.get("cve")

        if cve:
            allowed.add(
                str(cve).upper()
            )

    for report in event.get(
        "evidence_reports",
        [],
    ):
        for cve in report.get(
            "cves",
            [],
        ):
            if cve:
                allowed.add(
                    str(cve).upper()
                )

    return allowed


def build_nvd_index(event):
    """
    Build authoritative CVSS/CWE data from NVD.

    If NVD data is unavailable, we do not allow
    the AI to invent replacement values.
    """

    index = {}

    for record in event.get(
        "nvd",
        [],
    ):
        if not isinstance(record, dict):
            continue

        if record.get("error"):
            continue

        cve = record.get("cve")

        if not cve:
            continue

        cve = str(cve).upper()

        cvss = record.get("cvss")

        score = None

        if isinstance(cvss, dict):
            score = cvss.get(
                "score"
            )

        cwes = record.get(
            "cwes",
            [],
        )

        index[cve] = {
            "cvss": score,
            "cwes": list(cwes),
        }

    return index


def collect_candidate_iocs(event):
    """
    Build candidate IOC sets from deterministic
    extraction.

    Candidate does not mean confirmed malicious.
    """

    fields = (
        "ipv4",
        "domains",
        "urls",
        "md5",
        "sha1",
        "sha256",
    )

    allowed = {
        field: set()
        for field in fields
    }

    sources = [
        event.get(
            "iocs",
            {},
        )
    ]

    for report in event.get(
        "evidence_reports",
        [],
    ):
        sources.append(
            report.get(
                "iocs",
                {},
            )
        )

    for source in sources:
        for field in fields:
            for value in source.get(
                field,
                [],
            ):
                normalized = normalize(
                    value
                )

                if normalized:
                    allowed[field].add(
                        normalized
                    )

    return allowed


def validate_cves(event, analysis):
    """
    Remove CVEs introduced by AI that are not
    present in deterministic evidence.
    """

    allowed = collect_allowed_cves(
        event
    )

    accepted = []
    rejected = []

    for vulnerability in analysis.get(
        "vulnerabilities",
        [],
    ):
        cve = str(
            vulnerability.get(
                "cve",
                "",
            )
        ).upper()

        if cve in allowed:
            vulnerability["cve"] = cve

            accepted.append(
                vulnerability
            )
        else:
            rejected.append(
                {
                    "type": "unsupported_cve",
                    "value": cve,
                }
            )

    analysis["vulnerabilities"] = (
        accepted
    )

    return rejected


def enforce_nvd_fields(event, analysis):
    """
    CVSS and CWE values are deterministic fields.

    If NVD has data, force the AI result to use it.

    If NVD has no record, clear AI-provided CVSS
    and CWE values rather than trusting them.
    """

    nvd_index = build_nvd_index(
        event
    )

    corrections = []

    for vulnerability in analysis.get(
        "vulnerabilities",
        [],
    ):
        cve = str(
            vulnerability.get(
                "cve",
                "",
            )
        ).upper()

        nvd = nvd_index.get(
            cve
        )

        old_cvss = vulnerability.get(
            "cvss"
        )

        old_cwe = vulnerability.get(
            "cwe",
            [],
        )

        if nvd:
            correct_cvss = nvd.get(
                "cvss"
            )

            correct_cwe = nvd.get(
                "cwes",
                [],
            )
        else:
            correct_cvss = None
            correct_cwe = []

        if old_cvss != correct_cvss:
            corrections.append(
                {
                    "type": "cvss_corrected",
                    "cve": cve,
                    "ai_value": old_cvss,
                    "authoritative_value":
                        correct_cvss,
                }
            )

        if old_cwe != correct_cwe:
            corrections.append(
                {
                    "type": "cwe_corrected",
                    "cve": cve,
                    "ai_value": old_cwe,
                    "authoritative_value":
                        correct_cwe,
                }
            )

        vulnerability[
            "cvss"
        ] = correct_cvss

        vulnerability[
            "cwe"
        ] = correct_cwe

    return corrections


def validate_iocs(event, analysis):
    """
    Remove AI-returned IOCs that were not present
    in deterministic candidate evidence.

    Retention does not itself prove maliciousness.
    """

    allowed = collect_candidate_iocs(
        event
    )

    fields = (
        "ipv4",
        "domains",
        "urls",
        "md5",
        "sha1",
        "sha256",
    )

    analysis_iocs = analysis.get(
        "iocs",
        {},
    )

    rejected = []

    cleaned = {
        field: []
        for field in fields
    }

    for field in fields:
        for value in analysis_iocs.get(
            field,
            [],
        ):
            normalized = normalize(
                value
            )

            if normalized in allowed[field]:
                cleaned[field].append(
                    value
                )
            else:
                rejected.append(
                    {
                        "type": "unsupported_ioc",
                        "field": field,
                        "value": value,
                    }
                )

    analysis["iocs"] = cleaned

    return rejected


def validate_kev(event, analysis):
    """
    CISA KEV membership is deterministic.

    A supplied KEV match forces true.

    Without a supplied KEV match, an unsupported
    AI claim of true is changed to null.
    """

    kev_cves = {
        str(
            record.get("cve")
        ).upper()
        for record in event.get(
            "kev",
            [],
        )
        if record.get("cve")
    }

    rejected = []

    for vulnerability in analysis.get(
        "vulnerabilities",
        [],
    ):
        cve = str(
            vulnerability.get(
                "cve",
                "",
            )
        ).upper()

        ai_value = vulnerability.get(
            "cisa_kev"
        )

        if cve in kev_cves:
            vulnerability[
                "cisa_kev"
            ] = True

        elif ai_value is True:
            rejected.append(
                {
                    "type":
                        "unsupported_kev_claim",
                    "value": cve,
                }
            )

            vulnerability[
                "cisa_kev"
            ] = None

        elif ai_value is False:
            # No deterministic evidence currently
            # establishes an explicit KEV-negative
            # result, so false becomes unknown.
            vulnerability[
                "cisa_kev"
            ] = None

    return rejected


def ground_analysis(event, analysis):
    """
    Apply deterministic grounding to AI output.

    rejected:
        Unsupported claims removed.

    corrections:
        Deterministic values that replaced AI
        supplied values.
    """

    rejected = []
    corrections = []

    rejected.extend(
        validate_cves(
            event,
            analysis,
        )
    )

    corrections.extend(
        enforce_nvd_fields(
            event,
            analysis,
        )
    )

    rejected.extend(
        validate_iocs(
            event,
            analysis,
        )
    )

    rejected.extend(
        validate_kev(
            event,
            analysis,
        )
    )

    return {
        "analysis": analysis,
        "grounding": {
            "passed": (
                len(rejected) == 0
                and len(corrections) == 0
            ),
            "rejected": rejected,
            "rejected_count": len(
                rejected
            ),
            "corrections": corrections,
            "correction_count": len(
                corrections
            ),
        },
    }