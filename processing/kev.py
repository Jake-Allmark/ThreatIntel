import httpx


KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)


def download_kev():
    """
    Download the complete CISA KEV catalogue.

    The catalogue remains in memory for this program run.
    """

    response = httpx.get(
        KEV_URL,
        timeout=30.0,
        follow_redirects=True,
    )

    response.raise_for_status()

    data = response.json()

    return data.get("vulnerabilities", [])


def build_kev_index(vulnerabilities):
    """
    Build a fast lookup table keyed by CVE ID.
    """

    index = {}

    for vulnerability in vulnerabilities:
        cve = vulnerability.get("cveID")

        if not cve:
            continue

        index[cve.upper()] = vulnerability

    return index


def enrich_cves_with_kev(cves, kev_index):
    """
    Return KEV evidence for CVEs discovered in an article.
    """

    matches = []

    for cve in cves:
        kev_record = kev_index.get(
            cve.upper()
        )

        if not kev_record:
            continue

        matches.append(
            {
                "cve": cve.upper(),
                "vendor": kev_record.get(
                    "vendorProject"
                ),
                "product": kev_record.get(
                    "product"
                ),
                "vulnerability_name": kev_record.get(
                    "vulnerabilityName"
                ),
                "date_added": kev_record.get(
                    "dateAdded"
                ),
                "due_date": kev_record.get(
                    "dueDate"
                ),
                "ransomware_use": kev_record.get(
                    "knownRansomwareCampaignUse"
                ),
                "required_action": kev_record.get(
                    "requiredAction"
                ),
                "notes": kev_record.get(
                    "notes"
                ),
            }
        )

    return matches