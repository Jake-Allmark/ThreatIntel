from processing.textclean import (
    clean_inline_text,
    clean_text,
    truncate_text,
)


def check(name, condition):
    if not condition:
        raise AssertionError(
            f"FAIL - {name}"
        )

    print(
        f"PASS - {name}"
    )


html_sample = """
<h2 style="direction: ltr;">Overview</h2>
<p>
    A critical vulnerability affects
    <strong>BIG-IP APM</strong>.
</p>
<ul>
    <li>CVE-2026-94127</li>
    <li>CVSS 9.8</li>
</ul>
"""

cleaned = clean_text(
    html_sample
)

check(
    "HTML tags removed",
    "<h2" not in cleaned
    and "<p" not in cleaned
    and "<strong" not in cleaned,
)

check(
    "important text preserved",
    "BIG-IP APM" in cleaned
    and "CVE-2026-94127" in cleaned,
)


entity_sample = (
    "DepthFirst&nbsp;said "
    "hello&#xd;world"
)

entity_cleaned = clean_inline_text(
    entity_sample
)

check(
    "HTML entities decoded",
    "&nbsp;" not in entity_cleaned
    and "&#xd;" not in entity_cleaned,
)

check(
    "entity text preserved",
    "DepthFirst" in entity_cleaned
    and "world" in entity_cleaned,
)


unicode_sample = (
    "multi■user "
    "open■source "
    "non\u2011interactive"
)

unicode_cleaned = clean_inline_text(
    unicode_sample
)

check(
    "bad separator normalized",
    "multi-user" in unicode_cleaned
    and "open-source" in unicode_cleaned,
)

check(
    "nonbreaking hyphen normalized",
    "non-interactive" in unicode_cleaned,
)


double_encoded = (
    "&lt;p&gt;"
    "Threat actors exploit "
    "&lt;strong&gt;"
    "CVE-2026-12345"
    "&lt;/strong&gt;"
    "&lt;/p&gt;"
)

double_cleaned = clean_text(
    double_encoded
)

check(
    "double encoded HTML cleaned",
    "<p>" not in double_cleaned
    and "<strong>" not in double_cleaned,
)

check(
    "double encoded content preserved",
    "CVE-2026-12345" in double_cleaned,
)


inline_sample = """
<p>Hello</p>
<p>world</p>
"""

inline_cleaned = clean_inline_text(
    inline_sample
)

check(
    "inline mode produces one line",
    "\n" not in inline_cleaned,
)


long_sample = (
    "This is the first sentence. "
    "This is the second sentence. "
    "This is the third sentence. "
    * 20
)

truncated = truncate_text(
    long_sample,
    180,
)

check(
    "long text truncated",
    len(truncated) < len(long_sample),
)

check(
    "truncation marker added",
    truncated.endswith("[...]"),
)


print()
print(
    "All text-cleaning tests passed."
)