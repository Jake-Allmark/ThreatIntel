import ipaddress
import re
from urllib.parse import urlparse


CVE_PATTERN = re.compile(
    r"\bCVE-\d{4}-\d{4,7}\b",
    re.IGNORECASE,
)

URL_PATTERN = re.compile(
    r"https?://[^\s<>'\"\]\)]+",
    re.IGNORECASE,
)

IPV4_PATTERN = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
)

DOMAIN_PATTERN = re.compile(
    r"\b(?:[a-zA-Z0-9-]+\.)+"
    r"[a-zA-Z]{2,63}\b"
)

MD5_PATTERN = re.compile(
    r"\b[a-fA-F0-9]{32}\b"
)

SHA1_PATTERN = re.compile(
    r"\b[a-fA-F0-9]{40}\b"
)

SHA256_PATTERN = re.compile(
    r"\b[a-fA-F0-9]{64}\b"
)


def unique_sorted(values):
    """Remove duplicates and return sorted values."""
    return sorted(set(values))


def extract_cves(text):
    """Extract CVE identifiers."""
    matches = CVE_PATTERN.findall(text)

    return unique_sorted(
        match.upper()
        for match in matches
    )


def extract_urls(text):
    """Extract HTTP and HTTPS URLs."""
    matches = URL_PATTERN.findall(text)

    cleaned = []

    for url in matches:
        url = url.rstrip(".,;:")

        if url:
            cleaned.append(url)

    return unique_sorted(cleaned)


def extract_ipv4(text):
    """Extract and validate IPv4 addresses."""
    candidates = IPV4_PATTERN.findall(text)

    valid = []

    for candidate in candidates:
        try:
            address = ipaddress.ip_address(candidate)

            if address.version == 4:
                valid.append(str(address))

        except ValueError:
            continue

    return unique_sorted(valid)


def extract_domains(text, urls):
    """
    Extract domain names from text and URLs.
    """

    domains = DOMAIN_PATTERN.findall(text)

    for url in urls:
        try:
            hostname = urlparse(url).hostname

            if hostname:
                domains.append(hostname.lower())

        except ValueError:
            continue

    return unique_sorted(
        domain.lower()
        for domain in domains
    )


def extract_hashes(text):
    """Extract common cryptographic hash indicators."""

    return {
        "md5": unique_sorted(
            MD5_PATTERN.findall(text)
        ),
        "sha1": unique_sorted(
            SHA1_PATTERN.findall(text)
        ),
        "sha256": unique_sorted(
            SHA256_PATTERN.findall(text)
        ),
    }


def extract_intelligence(text):
    """
    Extract deterministic security indicators
    from supplied evidence.
    """

    urls = extract_urls(text)

    return {
        "cves": extract_cves(text),
        "ipv4": extract_ipv4(text),
        "domains": extract_domains(
            text,
            urls,
        ),
        "urls": urls,
        "hashes": extract_hashes(text),
    }