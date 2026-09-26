import os
import time

import httpx


NVD_API_URL = (
    "https://services.nvd.nist.gov/rest/json/cves/2.0"
)

_NVD_CACHE = {}

# Be conservative with NVD requests.
MIN_REQUEST_INTERVAL = 0.7

MAX_RETRIES = 4
INITIAL_BACKOFF_SECONDS = 2.0

_last_request_time = 0.0


def get_headers():
    headers = {
        "User-Agent": (
            "ThreatIntel/0.1 "
            "(defensive cybersecurity research)"
        )
    }

    api_key = os.getenv(
        "NVD_API_KEY"
    )

    if api_key:
        headers["apiKey"] = api_key

    return headers


def wait_for_rate_limit():
    """
    Ensure requests are not sent too quickly.

    This is intentionally conservative because
    ThreatIntel may request many CVEs in one run.
    """

    global _last_request_time

    now = time.monotonic()

    elapsed = (
        now - _last_request_time
    )

    remaining = (
        MIN_REQUEST_INTERVAL
        - elapsed
    )

    if remaining > 0:
        time.sleep(
            remaining
        )


def request_nvd(params):
    """
    Make an NVD request with retry/backoff.

    Retries:
    - HTTP 429 rate limiting
    - HTTP 500/502/503/504 temporary failures

    Other HTTP errors are raised immediately.
    """

    global _last_request_time

    backoff = (
        INITIAL_BACKOFF_SECONDS
    )

    for attempt in range(
        MAX_RETRIES + 1
    ):
        wait_for_rate_limit()

        response = httpx.get(
            NVD_API_URL,
            params=params,
            headers=get_headers(),
            timeout=30.0,
            follow_redirects=True,
        )

        _last_request_time = (
            time.monotonic()
        )

        if response.status_code == 200:
            return response

        retryable = (
            response.status_code == 429
            or response.status_code
            in {
                500,
                502,
                503,
                504,
            }
        )

        if not retryable:
            response.raise_for_status()

        if attempt >= MAX_RETRIES:
            response.raise_for_status()

        retry_after = (
            response.headers.get(
                "Retry-After"
            )
        )

        delay = backoff

        if retry_after:
            try:
                delay = max(
                    delay,
                    float(
                        retry_after
                    ),
                )

            except ValueError:
                pass

        time.sleep(
            delay
        )

        backoff *= 2

    raise RuntimeError(
        "NVD request failed after retries."
    )


def get_english_description(cve):
    for description in cve.get(
        "descriptions",
        [],
    ):
        if (
            description.get("lang")
            == "en"
        ):
            return description.get(
                "value",
                "",
            )

    return ""


def get_weaknesses(cve):
    weaknesses = set()

    for weakness in cve.get(
        "weaknesses",
        [],
    ):
        for description in weakness.get(
            "description",
            [],
        ):
            value = description.get(
                "value",
                "",
            )

            if value.startswith(
                "CWE-"
            ):
                weaknesses.add(
                    value
                )

    return sorted(
        weaknesses
    )


def get_cvss(cve):
    metrics = cve.get(
        "metrics",
        {},
    )

    versions = [
        (
            "4.0",
            "cvssMetricV40",
        ),
        (
            "3.1",
            "cvssMetricV31",
        ),
        (
            "3.0",
            "cvssMetricV30",
        ),
        (
            "2.0",
            "cvssMetricV2",
        ),
    ]

    for version, field in versions:
        records = metrics.get(
            field,
            [],
        )

        if not records:
            continue

        record = next(
            (
                item
                for item in records
                if item.get("type")
                == "Primary"
            ),
            records[0],
        )

        data = record.get(
            "cvssData",
            {},
        )

        return {
            "version": version,
            "score": data.get(
                "baseScore"
            ),
            "severity": (
                data.get(
                    "baseSeverity"
                )
                or record.get(
                    "baseSeverity"
                )
            ),
            "vector": data.get(
                "vectorString"
            ),
            "source": record.get(
                "source"
            ),
            "type": record.get(
                "type"
            ),
        }

    return None


def get_references(cve):
    references = []

    for reference in cve.get(
        "references",
        [],
    ):
        url = reference.get(
            "url"
        )

        if url:
            references.append(
                {
                    "url": url,
                    "source":
                        reference.get(
                            "source"
                        ),
                    "tags":
                        reference.get(
                            "tags",
                            [],
                        ),
                }
            )

    return references


def get_configurations(cve):
    return cve.get(
        "configurations",
        [],
    )


def fetch_nvd_cve(cve_id):
    """
    Retrieve one CVE from NVD.

    Results are cached only for the lifetime
    of the current Python process.
    """

    cve_id = cve_id.upper()

    if cve_id in _NVD_CACHE:
        return _NVD_CACHE[
            cve_id
        ]

    response = request_nvd(
        {
            "cveId": cve_id,
        }
    )

    data = response.json()

    vulnerabilities = data.get(
        "vulnerabilities",
        [],
    )

    if not vulnerabilities:
        _NVD_CACHE[
            cve_id
        ] = None

        return None

    cve = vulnerabilities[
        0
    ].get(
        "cve",
        {},
    )

    result = {
        "cve": cve.get(
            "id",
            cve_id,
        ),
        "status": cve.get(
            "vulnStatus"
        ),
        "published": cve.get(
            "published"
        ),
        "last_modified": cve.get(
            "lastModified"
        ),
        "description":
            get_english_description(
                cve
            ),
        "cvss": get_cvss(
            cve
        ),
        "cwes": get_weaknesses(
            cve
        ),
        "configurations":
            get_configurations(
                cve
            ),
        "references":
            get_references(
                cve
            ),
    }

    _NVD_CACHE[
        cve_id
    ] = result

    return result


def get_cache_size():
    return len(
        _NVD_CACHE
    )


def clear_cache():
    _NVD_CACHE.clear()