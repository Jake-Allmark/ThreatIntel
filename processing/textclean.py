import html
import re

from bs4 import BeautifulSoup


CONTROL_CHARACTERS = re.compile(
    r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]"
)

EXCESS_SPACES = re.compile(
    r"[ \t]+"
)

EXCESS_NEWLINES = re.compile(
    r"\n{3,}"
)

SPACE_BEFORE_PUNCTUATION = re.compile(
    r"\s+([,.;:!?])"
)


def normalize_unicode(text):
    replacements = {
        "\u00a0": " ",
        "\u200b": "",
        "\u200c": "",
        "\u200d": "",
        "\ufeff": "",
        "\u2010": "-",
        "\u2011": "-",
        "\u2012": "-",
        "\u2013": "-",
        "\u2212": "-",
        "\u25a0": "-",
        "\ufffd": "",
    }

    for old, new in replacements.items():
        text = text.replace(
            old,
            new,
        )

    return text


def html_to_text(value):
    if value is None:
        return ""

    text = str(value)

    if not text.strip():
        return ""

    #
    # Decode HTML entities first. Some feeds
    # contain HTML that has itself been encoded.
    #
    for _ in range(2):
        decoded = html.unescape(
            text
        )

        if decoded == text:
            break

        text = decoded

    soup = BeautifulSoup(
        text,
        "html.parser",
    )

    #
    # Remove content that should never appear
    # in a threat-intelligence narrative.
    #
    for element in soup(
        [
            "script",
            "style",
            "noscript",
            "svg",
        ]
    ):
        element.decompose()

    #
    # Add boundaries around block elements so
    # headings/list items do not run together.
    #
    for element in soup.find_all(
        [
            "p",
            "div",
            "section",
            "article",
            "h1",
            "h2",
            "h3",
            "h4",
            "li",
            "br",
        ]
    ):
        if element.name == "br":
            element.replace_with(
                "\n"
            )
            continue

        element.insert_before(
            "\n"
        )

        element.insert_after(
            "\n"
        )

    text = soup.get_text(
        separator=" ",
        strip=False,
    )

    return text


def clean_text(
    value,
    *,
    preserve_paragraphs=True,
):
    if value is None:
        return ""

    text = html_to_text(
        value
    )

    text = normalize_unicode(
        text
    )

    text = CONTROL_CHARACTERS.sub(
        "",
        text,
    )

    text = text.replace(
        "\r\n",
        "\n",
    )

    text = text.replace(
        "\r",
        "\n",
    )

    lines = []

    for raw_line in text.split(
        "\n"
    ):
        line = EXCESS_SPACES.sub(
            " ",
            raw_line,
        ).strip()

        line = SPACE_BEFORE_PUNCTUATION.sub(
            r"\1",
            line,
        )

        if line:
            lines.append(
                line
            )

        elif (
            preserve_paragraphs
            and lines
            and lines[-1] != ""
        ):
            lines.append(
                ""
            )

    if preserve_paragraphs:
        text = "\n".join(
            lines
        )

        text = EXCESS_NEWLINES.sub(
            "\n\n",
            text,
        )

    else:
        text = " ".join(
            line
            for line in lines
            if line
        )

    return text.strip()


def clean_inline_text(
    value,
):
    return clean_text(
        value,
        preserve_paragraphs=False,
    )


def truncate_text(
    value,
    max_chars,
):
    text = clean_text(
        value
    )

    if len(text) <= max_chars:
        return text

    shortened = text[
        :max_chars
    ].rstrip()

    #
    # Prefer ending on a sensible boundary.
    #
    boundary = max(
        shortened.rfind(". "),
        shortened.rfind("! "),
        shortened.rfind("? "),
        shortened.rfind("\n"),
    )

    if boundary >= int(
        max_chars * 0.60
    ):
        shortened = shortened[
            :boundary + 1
        ].rstrip()

    return (
        shortened
        + " [...]"
    )