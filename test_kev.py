from processing.kev import (
    download_kev,
    build_kev_index,
    enrich_cves_with_kev,
)


print("Downloading CISA KEV...")

vulnerabilities = download_kev()
kev_index = build_kev_index(vulnerabilities)

print(
    f"Loaded {len(kev_index):,} KEV records."
)


# Instead of hard-coding a CVE, use the first
# real CVE currently present in CISA KEV.
test_cve = vulnerabilities[0]["cveID"]

print()
print(f"Testing CVE: {test_cve}")

matches = enrich_cves_with_kev(
    [test_cve],
    kev_index,
)

print()

if matches:
    print("KEV MATCH FOUND")
    print()

    match = matches[0]

    print(f"CVE: {match['cve']}")
    print(f"Vendor: {match['vendor']}")
    print(f"Product: {match['product']}")
    print(
        "Vulnerability: "
        f"{match['vulnerability_name']}"
    )
    print(
        f"Date added: {match['date_added']}"
    )
    print(
        f"Due date: {match['due_date']}"
    )
    print(
        "Known ransomware use: "
        f"{match['ransomware_use']}"
    )
    print()
    print("CISA required action:")
    print(match["required_action"])

else:
    print("No KEV match found.")