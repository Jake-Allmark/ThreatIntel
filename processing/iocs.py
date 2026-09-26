import ipaddress
from urllib.parse import urlparse


KNOWN_INFORMATION_DOMAINS = {
    "cisa.gov",
    "nvd.nist.gov",
    "nist.gov",
    "microsoft.com",
    "github.com",
    "google.com",
    "cloud.google.com",
    "bleepingcomputer.com",
    "securityweek.com",
    "thehackernews.com",
    "ncsc.gov.uk",
    "cert.org",
}


def normalize_domain(value):
    value = (value or "").strip().lower()
    value = value.rstrip(".")

    if value.startswith("www."):
        value = value[4:]

    return value


def domain_matches(domain, known_domain):
    domain = normalize_domain(domain)
    known_domain = normalize_domain(known_domain)

    return (
        domain == known_domain
        or domain.endswith(
            "." + known_domain
        )
    )


def is_information_domain(domain):
    domain = normalize_domain(domain)

    return any(
        domain_matches(
            domain,
            known_domain,
        )
        for known_domain
        in KNOWN_INFORMATION_DOMAINS
    )


def hostname_from_url(url):
    try:
        return normalize_domain(
            urlparse(url).hostname
        )
    except (TypeError, ValueError):
        return ""


def is_public_ipv4(value):
    try:
        address = ipaddress.ip_address(
            value
        )

        return (
            address.version == 4
            and address.is_global
        )

    except ValueError:
        return False


def classify_iocs(
    iocs,
    source_url="",
):
    """
    Classify extracted indicators.

    candidate:
        Technically plausible indicators which
        require contextual validation.

    informational:
        Domains/URLs that appear to be
        information or source infrastructure.

    excluded:
        Invalid/non-public network indicators.

    IMPORTANT:
        A candidate IOC is NOT automatically
        confirmed malicious.
    """

    #
    # extract_intelligence() stores hashes
    # inside:
    #
    #   {
    #       "hashes": {
    #           "md5": [],
    #           "sha1": [],
    #           "sha256": []
    #       }
    #   }
    #
    # Older tests also supplied hashes directly
    # at the top level. Support both forms.
    #
    nested_hashes = iocs.get(
        "hashes",
        {},
    ) or {}

    candidate = {
        "ipv4": [],
        "domains": [],
        "urls": [],
        "md5": list(
            iocs.get(
                "md5",
                nested_hashes.get(
                    "md5",
                    [],
                ),
            )
        ),
        "sha1": list(
            iocs.get(
                "sha1",
                nested_hashes.get(
                    "sha1",
                    [],
                ),
            )
        ),
        "sha256": list(
            iocs.get(
                "sha256",
                nested_hashes.get(
                    "sha256",
                    [],
                ),
            )
        ),
    }

    informational = {
        "ipv4": [],
        "domains": [],
        "urls": [],
    }

    excluded = {
        "ipv4": [],
        "domains": [],
        "urls": [],
    }

    source_domain = hostname_from_url(
        source_url
    )

    #
    # IPv4 addresses
    #
    for value in iocs.get(
        "ipv4",
        [],
    ):
        if is_public_ipv4(value):
            candidate["ipv4"].append(
                value
            )
        else:
            excluded["ipv4"].append(
                value
            )

    #
    # Domains
    #
    for value in iocs.get(
        "domains",
        [],
    ):
        domain = normalize_domain(
            value
        )

        if not domain:
            continue

        if (
            source_domain
            and domain_matches(
                domain,
                source_domain,
            )
        ):
            informational[
                "domains"
            ].append(
                domain
            )

        elif is_information_domain(
            domain
        ):
            informational[
                "domains"
            ].append(
                domain
            )

        else:
            candidate[
                "domains"
            ].append(
                domain
            )

    #
    # URLs
    #
    for value in iocs.get(
        "urls",
        [],
    ):
        domain = hostname_from_url(
            value
        )

        if not domain:
            excluded["urls"].append(
                value
            )
            continue

        if (
            source_domain
            and domain_matches(
                domain,
                source_domain,
            )
        ):
            informational[
                "urls"
            ].append(
                value
            )

        elif is_information_domain(
            domain
        ):
            informational[
                "urls"
            ].append(
                value
            )

        else:
            candidate[
                "urls"
            ].append(
                value
            )

    #
    # Remove duplicates while preserving
    # deterministic ordering.
    #
    for group in (
        candidate,
        informational,
        excluded,
    ):
        for key, values in group.items():
            group[key] = sorted(
                set(values)
            )

    return {
        "candidate": candidate,
        "informational": informational,
        "excluded": excluded,
    }