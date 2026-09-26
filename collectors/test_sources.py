from collectors.sources import (
    get_enabled_feeds,
    get_source_counts,
    get_target_sources,
)


feeds = get_enabled_feeds()
targets = get_target_sources()
counts = get_source_counts()


assert len(feeds) == 23, (
    f"Expected 23 direct feeds, got {len(feeds)}"
)

assert len(targets) == 30, (
    f"Expected 30 target services, got {len(targets)}"
)

assert counts["total"] == 30

assert counts["enabled"] == 23, (
    f"Expected 23 enabled, got {counts['enabled']}"
)

assert counts["enrichment"] == 2, (
    f"Expected 2 enrichment services, "
    f"got {counts['enrichment']}"
)

assert counts["pending"] == 5, (
    f"Expected 5 pending, got {counts['pending']}"
)


expected_pending = {
    "CISA Cybersecurity Advisories",
    "MSRC",
    "Sophos X-Ops",
    "Trend Micro Research",
    "Fortinet FortiGuard Labs",
}


actual_pending = {
    source["name"]
    for source in targets
    if source["status"] == "pending"
}


assert actual_pending == expected_pending, (
    "Unexpected pending sources.\n"
    f"Expected: {sorted(expected_pending)}\n"
    f"Actual: {sorted(actual_pending)}"
)


urls = [
    source["url"]
    for source in feeds
]

assert len(urls) == len(set(urls)), (
    "Duplicate feed URLs detected"
)


for source in feeds:
    assert source.get("name"), (
        "Feed missing name"
    )

    assert source.get("url"), (
        f"{source.get('name')} missing URL"
    )

    assert source.get("category"), (
        f"{source.get('name')} missing category"
    )

    assert source.get("enabled") is True, (
        f"{source.get('name')} is not enabled"
    )


print(
    "PASS - direct collectors:",
    len(feeds),
)

print(
    "PASS - enrichment services:",
    counts["enrichment"],
)

print(
    "PASS - pending integrations:",
    counts["pending"],
)

print(
    "PASS - total target services:",
    counts["total"],
)

print("PASS - feed URLs unique")
print("PASS - pending registry correct")

print(
    "\nAll source registry tests passed."
)