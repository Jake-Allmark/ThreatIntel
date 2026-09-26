from processing.iocs import classify_iocs


raw_iocs = {
    "ipv4": [
        "8.8.8.8",
        "192.168.1.10",
        "127.0.0.1",
    ],
    "domains": [
        "evil-example.test",
        "www.bleepingcomputer.com",
        "nvd.nist.gov",
    ],
    "urls": [
        "https://evil-example.test/payload",
        "https://www.bleepingcomputer.com/news/security/example",
        "https://nvd.nist.gov/vuln/detail/CVE-2026-12345",
    ],
    "md5": [
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    ],
    "sha1": [],
    "sha256": [
        (
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        ),
    ],
}


result = classify_iocs(
    raw_iocs,
    source_url=(
        "https://www.bleepingcomputer.com/"
        "news/security/example"
    ),
)


candidate = result["candidate"]
informational = result["informational"]
excluded = result["excluded"]


assert "8.8.8.8" in candidate["ipv4"]

assert (
    "192.168.1.10"
    in excluded["ipv4"]
)

assert (
    "127.0.0.1"
    in excluded["ipv4"]
)

assert (
    "evil-example.test"
    in candidate["domains"]
)

assert (
    "bleepingcomputer.com"
    in informational["domains"]
)

assert (
    "nvd.nist.gov"
    in informational["domains"]
)

assert (
    "https://evil-example.test/payload"
    in candidate["urls"]
)

assert len(
    candidate["md5"]
) == 1

assert len(
    candidate["sha256"]
) == 1


print(
    "PASS - public IP remains candidate"
)

print(
    "PASS - private/local IPs excluded"
)

print(
    "PASS - source domains classified as informational"
)

print(
    "PASS - NVD/security domains classified as informational"
)

print(
    "PASS - suspicious domain remains candidate"
)

print(
    "PASS - candidate hashes preserved"
)

print(
    "\nAll IOC classification tests passed."
)