import json
import re
from pathlib import Path


PROJECT_ROOT = (
    Path(__file__)
    .resolve()
    .parent
    .parent
)

DEFAULT_CATALOGUE = (
    PROJECT_ROOT
    / "config"
    / "managed_technologies.json"
)


# Very short aliases are useful in the catalogue, but are unsafe when
# searching ordinary prose. For example, "MDE" is fine in a product
# title but should not be trusted as a loose article-body match.
MIN_PROSE_ALIAS_LENGTH = 4


def load_catalogue(path=None):
    catalogue_path = (
        Path(path)
        if path
        else DEFAULT_CATALOGUE
    )

    with catalogue_path.open(
        "r",
        encoding="utf-8",
    ) as file:
        data = json.load(file)

    return data.get(
        "technologies",
        [],
    )


def normalize(value):
    if value is None:
        return ""

    text = str(value).lower()

    text = re.sub(
        r"[^a-z0-9+#.\-]+",
        " ",
        text,
    )

    return re.sub(
        r"\s+",
        " ",
        text,
    ).strip()


def alias_matches(alias, text):
    alias_normalized = normalize(alias)

    if not alias_normalized:
        return False

    text_normalized = normalize(text)

    pattern = (
        r"(?<![a-z0-9])"
        + re.escape(alias_normalized)
        + r"(?![a-z0-9])"
    )

    return (
        re.search(
            pattern,
            text_normalized,
        )
        is not None
    )


def alias_is_safe_for_prose(alias):
    """
    Short aliases can produce accidental matches in prose.

    They remain valid for structured evidence such as KEV/CPE data,
    but ordinary title/summary matching requires a slightly safer
    alias.
    """

    compact = re.sub(
        r"[^a-z0-9]",
        "",
        normalize(alias),
    )

    return (
        len(compact)
        >= MIN_PROSE_ALIAS_LENGTH
    )


def unique(values):
    seen = set()
    output = []

    for value in values:
        if not value:
            continue

        key = normalize(value)

        if not key:
            continue

        if key in seen:
            continue

        seen.add(key)
        output.append(value)

    return output


def get_kev_evidence(event):
    """
    KEV is structured affected-product evidence.

    We intentionally use vendor/product/vulnerability name only.
    Notes and required-action prose are excluded because they can
    contain unrelated technology names and links.
    """

    results = []

    for item in (
        event.get("kev", [])
        or []
    ):
        if not isinstance(
            item,
            dict,
        ):
            continue

        values = []

        for field in (
            "vendor",
            "product",
            "vulnerability_name",
        ):
            value = item.get(field)

            if value:
                values.append(
                    str(value)
                )

        if values:
            results.append(
                {
                    "cve": item.get(
                        "cve"
                    ),
                    "text": " ".join(
                        values
                    ),
                }
            )

    return results


def parse_cpe(criteria):
    """
    Parse the vendor/product portion of a CPE 2.3 string.

    Example:
        cpe:2.3:a:f5:big-ip_access_policy_manager:...

    Returns:
        {
            "vendor": "f5",
            "product": "big-ip access policy manager"
        }
    """

    if not isinstance(
        criteria,
        str,
    ):
        return None

    parts = criteria.split(":")

    if (
        len(parts) < 5
        or parts[0] != "cpe"
        or parts[1] != "2.3"
    ):
        return None

    vendor = (
        parts[3]
        .replace("_", " ")
        .replace("\\", "")
    )

    product = (
        parts[4]
        .replace("_", " ")
        .replace("\\", "")
    )

    return {
        "vendor": vendor,
        "product": product,
    }


def get_nvd_cpe_evidence(event):
    """
    Extract only vulnerable CPE entries from NVD configurations.

    NVD descriptions and references are deliberately NOT used for
    customer-estate matching because they may mention unrelated
    vendors/products.
    """

    results = []

    for nvd_item in (
        event.get("nvd", [])
        or []
    ):
        if not isinstance(
            nvd_item,
            dict,
        ):
            continue

        cve = nvd_item.get("cve")

        configurations = (
            nvd_item.get(
                "configurations",
                [],
            )
            or []
        )

        for configuration in configurations:
            if not isinstance(
                configuration,
                dict,
            ):
                continue

            nodes = (
                configuration.get(
                    "nodes",
                    [],
                )
                or []
            )

            for node in nodes:
                if not isinstance(
                    node,
                    dict,
                ):
                    continue

                cpe_matches = (
                    node.get(
                        "cpeMatch",
                        [],
                    )
                    or []
                )

                for cpe_match in cpe_matches:
                    if not isinstance(
                        cpe_match,
                        dict,
                    ):
                        continue

                    if not cpe_match.get(
                        "vulnerable",
                        False,
                    ):
                        continue

                    parsed = parse_cpe(
                        cpe_match.get(
                            "criteria"
                        )
                    )

                    if not parsed:
                        continue

                    results.append(
                        {
                            "cve": cve,
                            "vendor": parsed[
                                "vendor"
                            ],
                            "product": parsed[
                                "product"
                            ],
                            "criteria": cpe_match.get(
                                "criteria"
                            ),
                            "version_start_including": (
                                cpe_match.get(
                                    "versionStartIncluding"
                                )
                            ),
                            "version_start_excluding": (
                                cpe_match.get(
                                    "versionStartExcluding"
                                )
                            ),
                            "version_end_including": (
                                cpe_match.get(
                                    "versionEndIncluding"
                                )
                            ),
                            "version_end_excluding": (
                                cpe_match.get(
                                    "versionEndExcluding"
                                )
                            ),
                        }
                    )

    return results


def get_primary_text_evidence(event):
    """
    Limited source text allowed to create a managed-estate match.

    Full article/evidence bodies are intentionally excluded.

    The event title is the only unstructured prose source allowed
    to create a match. The event summary is retained here for future
    contextual use but is not used to create estate relevance.
    """

    return {
        "title": str(
            event.get(
                "title",
                "",
            )
            or ""
        ),
        "summary": str(
            event.get(
                "summary",
                "",
            )
            or ""
        ),
    }


def aliases_matching_text(
    aliases,
    text,
    prose=False,
):
    matches = []

    for alias in aliases:
        if (
            prose
            and not alias_is_safe_for_prose(
                alias
            )
        ):
            continue

        if alias_matches(
            alias,
            text,
        ):
            matches.append(alias)

    return unique(matches)


def find_matching_aliases(
    event,
    catalogue=None,
):
    """
    Match managed technologies using evidence tiers.

    Strong:
        NVD vulnerable CPE
        CISA KEV vendor/product

    Medium:
        Primary event title

    Not sufficient to create a match:
        Primary event summary

    Explicitly excluded:
        article_text
        evidence_text
        arbitrary evidence_reports body text
        NVD references/descriptions
        KEV notes/actions
        AI-generated analysis

    This prevents navigation links, related stories, advertisements,
    and incidental mentions from creating customer exposure.
    """

    if catalogue is None:
        catalogue = load_catalogue()

    nvd_evidence = (
        get_nvd_cpe_evidence(
            event
        )
    )

    kev_evidence = (
        get_kev_evidence(
            event
        )
    )

    primary = (
        get_primary_text_evidence(
            event
        )
    )

    matches = []

    for technology in catalogue:
        name = technology.get(
            "name",
            "Unknown",
        )

        aliases = technology.get(
            "aliases",
            [],
        )

        evidence = []
        matched_aliases = []

        # ---------------------------------
        # Strongest: NVD vulnerable CPE
        # ---------------------------------

        for item in nvd_evidence:
            cpe_text = " ".join(
                [
                    str(
                        item.get(
                            "vendor",
                            "",
                        )
                    ),
                    str(
                        item.get(
                            "product",
                            "",
                        )
                    ),
                ]
            )

            aliases_found = (
                aliases_matching_text(
                    aliases,
                    cpe_text,
                    prose=False,
                )
            )

            if aliases_found:
                matched_aliases.extend(
                    aliases_found
                )

                evidence.append(
                    {
                        "type": "NVD_CPE",
                        "strength": "STRONG",
                        "cve": item.get(
                            "cve"
                        ),
                        "vendor": item.get(
                            "vendor"
                        ),
                        "product": item.get(
                            "product"
                        ),
                        "criteria": item.get(
                            "criteria"
                        ),
                        "version_start_including": (
                            item.get(
                                "version_start_including"
                            )
                        ),
                        "version_start_excluding": (
                            item.get(
                                "version_start_excluding"
                            )
                        ),
                        "version_end_including": (
                            item.get(
                                "version_end_including"
                            )
                        ),
                        "version_end_excluding": (
                            item.get(
                                "version_end_excluding"
                            )
                        ),
                    }
                )

        # ---------------------------------
        # Strong: KEV affected vendor/product
        # ---------------------------------

        for item in kev_evidence:
            aliases_found = (
                aliases_matching_text(
                    aliases,
                    item.get(
                        "text",
                        "",
                    ),
                    prose=False,
                )
            )

            if aliases_found:
                matched_aliases.extend(
                    aliases_found
                )

                evidence.append(
                    {
                        "type": "KEV_PRODUCT",
                        "strength": "STRONG",
                        "cve": item.get(
                            "cve"
                        ),
                        "text": item.get(
                            "text"
                        ),
                    }
                )

        # ---------------------------------
        # Medium: event title
        # ---------------------------------

        title_aliases = (
            aliases_matching_text(
                aliases,
                primary["title"],
                prose=True,
            )
        )

        if title_aliases:
            matched_aliases.extend(
                title_aliases
            )

            evidence.append(
                {
                    "type": "TITLE",
                    "strength": "MEDIUM",
                    "text": primary[
                        "title"
                    ],
                }
            )

        # ---------------------------------
        # Weak signal: event summary
        # ---------------------------------
        #
        # Summary-only technology references are intentionally not
        # allowed to create managed-estate relevance. Summaries can
        # contain incidental vendor/product references that do not
        # describe the affected technology.
        #
        # Authoritative NVD/KEV evidence and primary-title matches
        # remain eligible above.

        if evidence:
            matches.append(
                {
                    "technology": name,
                    "matched_aliases": (
                        unique(
                            matched_aliases
                        )
                    ),
                    "evidence": evidence,
                }
            )

    return matches


def evidence_types(match):
    return {
        item.get("type")
        for item in (
            match.get(
                "evidence",
                [],
            )
            or []
        )
        if isinstance(
            item,
            dict,
        )
    }


def determine_match_level(
    event,
    match,
):
    """
    Match level is determined by evidence attached to THIS managed
    technology, not merely by whether the overall event contains a
    CVE/KEV/exploitation signal.

    This prevents:
        unrelated Microsoft mention + F5 KEV
    from becoming:
        Microsoft PRODUCT_KEV
    """

    types = evidence_types(
        match
    )

    priority = (
        event.get(
            "priority",
            {},
        )
        or {}
    )

    active_exploitation = bool(
        priority.get(
            "active_exploitation_language",
            False,
        )
    )

    if (
        active_exploitation
        and (
            "NVD_CPE" in types
            or "KEV_PRODUCT" in types
        )
    ):
        return (
            "PRODUCT_ACTIVE_EXPLOITATION"
        )

    if "KEV_PRODUCT" in types:
        return "PRODUCT_KEV"

    if "NVD_CPE" in types:
        return "PRODUCT_CVE"

    if "TITLE" in types:
        return "PRODUCT_MENTION"

    return "TECHNOLOGY_MENTION"


def determine_match_basis(match):
    types = evidence_types(
        match
    )

    if "NVD_CPE" in types:
        return (
            "NVD affected-product CPE"
        )

    if "KEV_PRODUCT" in types:
        return (
            "CISA KEV affected product"
        )

    if "TITLE" in types:
        return "Primary report title"

    if "SUMMARY" in types:
        return "Primary report summary"

    return "Unknown"


def correlate_customer_assets(
    event,
    catalogue=None,
):
    matches = find_matching_aliases(
        event,
        catalogue=catalogue,
    )

    technologies = []

    for match in matches:
        enriched_match = dict(
            match
        )

        enriched_match[
            "match_level"
        ] = determine_match_level(
            event,
            match,
        )

        enriched_match[
            "match_basis"
        ] = determine_match_basis(
            match
        )

        technologies.append(
            enriched_match
        )

    result = {
        "relevant": bool(
            technologies
        ),
        "managed_technologies": technologies,
        "technology_count": len(
            technologies
        ),

        # This field MUST remain false in the MVP because the tool
        # does not hold customer deployment/version/patch inventory.
        "exposure_confirmed": False,

        "requires_validation": bool(
            technologies
        ),
    }

    if technologies:
        result[
            "analyst_note"
        ] = (
            "Managed technology relevance detected. "
            "This does not confirm customer vulnerability "
            "or exposure. Validate deployed product, version, "
            "configuration, internet exposure and patch state."
        )

    else:
        result[
            "analyst_note"
        ] = (
            "No managed technology match was detected "
            "from authoritative affected-product evidence "
            "or the primary report title."
        )

    return result


def apply_customer_asset_correlation(
    events,
    catalogue=None,
):
    if catalogue is None:
        catalogue = load_catalogue()

    for event in events:
        event[
            "customer_asset_exposure"
        ] = correlate_customer_assets(
            event,
            catalogue=catalogue,
        )

    return events