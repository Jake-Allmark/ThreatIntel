import re

import httpx
from bs4 import BeautifulSoup


HEADERS = {
    "User-Agent": (
        "ThreatIntel/0.1 "
        "(defensive cybersecurity research)"
    )
}


def clean_text(text):
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def fetch_article(url):
    """
    Retrieve a public article/advisory and extract readable text.

    If retrieval fails, callers can fall back to RSS/API content.
    """

    if not url:
        return ""

    response = httpx.get(
        url,
        headers=HEADERS,
        timeout=20.0,
        follow_redirects=True,
    )

    response.raise_for_status()

    content_type = response.headers.get(
        "content-type",
        "",
    ).lower()

    if "html" not in content_type:
        return ""

    soup = BeautifulSoup(
        response.text,
        "html.parser",
    )

    # Remove content that isn't part of the article.
    for element in soup(
        [
            "script",
            "style",
            "nav",
            "footer",
            "header",
            "form",
            "noscript",
            "svg",
        ]
    ):
        element.decompose()

    # Prefer the semantic article element.
    article = soup.find("article")

    if article:
        paragraphs = article.find_all(
            ["p", "h1", "h2", "h3", "li"]
        )
    else:
        paragraphs = soup.find_all("p")

    pieces = []

    for paragraph in paragraphs:
        text = clean_text(
            paragraph.get_text(
                " ",
                strip=True,
            )
        )

        # Ignore tiny navigation fragments.
        if len(text) >= 30:
            pieces.append(text)

    result = "\n\n".join(pieces)

    # Safety limit for one article.
    return result[:100_000]