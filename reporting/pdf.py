from datetime import datetime
from pathlib import Path
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    HRFlowable,
    KeepTogether,
    PageBreak,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)

from processing.textclean import clean_inline_text


PAGE_WIDTH, PAGE_HEIGHT = A4

BACKGROUND = colors.HexColor("#07111F")
PANEL = colors.HexColor("#0D1B2A")
PANEL_ALT = colors.HexColor("#10243A")
TEXT = colors.HexColor("#E8EEF5")
MUTED = colors.HexColor("#93A4B8")
ACCENT = colors.HexColor("#22D3EE")
BORDER = colors.HexColor("#24364B")

CRITICAL = colors.HexColor("#EF4444")
HIGH = colors.HexColor("#F97316")
MEDIUM = colors.HexColor("#FACC15")
INFO = colors.HexColor("#38BDF8")
CONTEXT = colors.HexColor("#A78BFA")
SUCCESS = colors.HexColor("#22C55E")
CUSTOMER = colors.HexColor("#14B8A6")

PRIORITY_ORDER = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "INFORMATIONAL": 3,
}


def safe(value, fallback="Unknown"):
    if value is None:
        return escape(fallback)

    text = clean_inline_text(str(value)).strip()

    if not text:
        return escape(fallback)

    return escape(text)


def safe_list(values):
    if not values:
        return ""

    cleaned = []

    for value in values:
        if value is None:
            continue

        if isinstance(value, dict):
            continue

        text = clean_inline_text(str(value)).strip()

        if text:
            cleaned.append(text)

    return ", ".join(cleaned)


def priority_color(level):
    return {
        "CRITICAL": CRITICAL,
        "HIGH": HIGH,
        "MEDIUM": MEDIUM,
        "INFORMATIONAL": INFO,
    }.get(
        str(level).upper(),
        MUTED,
    )


def get_priority(event):
    priority = event.get("priority", {}) or {}
    return str(
        priority.get(
            "level",
            "INFORMATIONAL",
        )
    ).upper()


def get_relevance(event):
    relevance = event.get("relevance", {}) or {}
    return str(
        relevance.get(
            "classification",
            "CONTEXT",
        )
    ).upper()


def sort_events(events):
    return sorted(
        events,
        key=lambda event: (
            PRIORITY_ORDER.get(
                get_priority(event),
                99,
            ),
            -float(
                (
                    event.get(
                        "priority",
                        {},
                    )
                    or {}
                ).get(
                    "score",
                    0,
                )
                or 0
            ),
            str(
                event.get(
                    "title",
                    "",
                )
            ).lower(),
        ),
    )


def split_events(events):
    threats = []
    context = []
    non_threat = []

    for event in events:
        classification = get_relevance(event)

        if classification == "THREAT":
            threats.append(event)

        elif classification == "NON_THREAT":
            non_threat.append(event)

        else:
            context.append(event)

    return (
        sort_events(threats),
        context,
        non_threat,
    )


def get_ai(event):
    return (
        event.get("ai")
        or event.get("ai_enrichment")
        or {}
    )


def first_value(mapping, keys):
    if not isinstance(mapping, dict):
        return None

    for key in keys:
        value = mapping.get(key)

        if value not in (
            None,
            "",
            [],
            {},
        ):
            return value

    return None


def text_value(value):
    if value is None:
        return ""

    if isinstance(value, str):
        return clean_inline_text(value)

    if isinstance(value, list):
        parts = []

        for item in value:
            if isinstance(item, str):
                cleaned = clean_inline_text(item)

                if cleaned:
                    parts.append(cleaned)

            elif isinstance(item, dict):
                action = (
                    item.get("action")
                    or item.get("name")
                    or item.get("value")
                    or item.get("activity")
                )

                reason = (
                    item.get("reason")
                    or item.get("why")
                    or item.get("evidence_basis")
                )

                if action and reason:
                    parts.append(
                        f"{action} - {reason}"
                    )

                elif action:
                    parts.append(str(action))

        return "; ".join(parts)

    if isinstance(value, dict):
        parts = []

        for key, item in value.items():
            if item in (
                None,
                "",
                [],
                {},
            ):
                continue

            if isinstance(
                item,
                (
                    str,
                    int,
                    float,
                    bool,
                ),
            ):
                parts.append(
                    f"{key}: {item}"
                )

        return "; ".join(parts)

    return clean_inline_text(str(value))


def get_summary(event):
    ai = get_ai(event)

    value = first_value(
        ai,
        (
            "executive_summary",
            "summary",
            "what_is_it",
        ),
    )

    if value:
        return text_value(value)

    return (
        text_value(
            event.get("summary")
        )
        or
        "No analytical summary was available "
        "for this event."
    )


def get_what_is_it(event):
    ai = get_ai(event)

    value = first_value(
        ai,
        (
            "what_is_it",
            "description",
        ),
    )

    return text_value(value)


def get_affected_technologies(event):
    ai = get_ai(event)

    value = first_value(
        ai,
        (
            "affected_technologies",
            "affected_technology",
            "technologies",
        ),
    )

    return text_value(value)


def get_potential_impact(event):
    ai = get_ai(event)

    return text_value(
        first_value(
            ai,
            (
                "potential_impact",
                "impact",
            ),
        )
    )


def get_actions(event):
    ai = get_ai(event)

    return text_value(
        first_value(
            ai,
            (
                "recommended_actions",
                "actions",
            ),
        )
    )


def get_intelligence_gaps(event):
    ai = get_ai(event)

    return text_value(
        first_value(
            ai,
            (
                "intelligence_gaps",
                "unknowns",
                "gaps",
            ),
        )
    )


def get_confidence(event):
    ai = get_ai(event)

    confidence = first_value(
        ai,
        (
            "confidence",
            "confidence_level",
        ),
    )

    if confidence:
        return text_value(confidence)

    return "Not AI-assessed"


def get_exploitation(event):
    ai = get_ai(event)

    exploitation = ai.get(
        "exploitation"
    )

    ai_text = text_value(exploitation)

    priority = event.get(
        "priority",
        {},
    ) or {}

    deterministic = priority.get(
        "active_exploitation_language"
    )

    if deterministic:
        source = priority.get(
            "exploitation_evidence_source",
            "report evidence",
        )

        return (
            "Current exploitation language detected "
            f"from {source}."
        )

    if ai_text:
        return ai_text

    return (
        "No confirmed current exploitation "
        "evidence recorded."
    )


def get_source_names(event):
    names = []

    for source in (
        event.get(
            "sources",
            [],
        )
        or []
    ):
        if isinstance(source, dict):
            name = (
                source.get("publisher")
                or source.get("source")
                or source.get("name")
            )

            if name:
                names.append(
                    clean_inline_text(
                        str(name)
                    )
                )

        elif source:
            names.append(
                clean_inline_text(
                    str(source)
                )
            )

    if not names:
        source = event.get("source")

        if source:
            names.append(
                clean_inline_text(
                    str(source)
                )
            )

    return list(
        dict.fromkeys(names)
    )


def get_candidate_iocs(event):
    iocs = event.get(
        "iocs",
        {},
    ) or {}

    candidate = iocs.get(
        "candidate",
        {},
    )

    if isinstance(candidate, dict):
        total = 0

        for values in candidate.values():
            if isinstance(values, list):
                total += len(values)

        return total

    if isinstance(candidate, list):
        return len(candidate)

    classification = event.get(
        "ioc_classification",
        {},
    ) or {}

    direct = classification.get(
        "candidate",
        [],
    )

    if isinstance(direct, list):
        return len(direct)

    return 0


def get_customer_exposure(event):
    return (
        event.get(
            "customer_asset_exposure",
            {},
        )
        or {}
    )


def customer_relevant(event):
    return bool(
        get_customer_exposure(
            event
        ).get(
            "relevant",
            False,
        )
    )


def get_customer_technologies(event):
    exposure = get_customer_exposure(event)

    for key in (
        "technologies",
        "matched_technologies",
        "products",
        "matches",
    ):
        values = exposure.get(key)

        if not values:
            continue

        names = []

        if isinstance(values, list):
            for value in values:
                if isinstance(value, str):
                    names.append(value)

                elif isinstance(value, dict):
                    name = (
                        value.get("technology")
                        or value.get("product")
                        or value.get("name")
                        or value.get("display_name")
                    )

                    if name:
                        names.append(
                            str(name)
                        )

        elif isinstance(values, str):
            names.append(values)

        if names:
            return list(
                dict.fromkeys(names)
            )

    return []


def build_styles():
    return {
        "cover_label": ParagraphStyle(
            "cover_label",
            fontName="Helvetica-Bold",
            fontSize=10,
            leading=14,
            textColor=ACCENT,
            alignment=TA_CENTER,
            spaceAfter=8,
        ),
        "cover_title": ParagraphStyle(
            "cover_title",
            fontName="Helvetica-Bold",
            fontSize=29,
            leading=33,
            textColor=TEXT,
            alignment=TA_CENTER,
            spaceAfter=12,
        ),
        "cover_subtitle": ParagraphStyle(
            "cover_subtitle",
            fontName="Helvetica",
            fontSize=11,
            leading=16,
            textColor=MUTED,
            alignment=TA_CENTER,
        ),
        "section": ParagraphStyle(
            "section",
            fontName="Helvetica-Bold",
            fontSize=17,
            leading=21,
            textColor=TEXT,
            spaceBefore=5,
            spaceAfter=5,
        ),
        "section_note": ParagraphStyle(
            "section_note",
            fontName="Helvetica",
            fontSize=8,
            leading=11,
            textColor=MUTED,
            spaceAfter=10,
        ),
        "event_title": ParagraphStyle(
            "event_title",
            fontName="Helvetica-Bold",
            fontSize=11,
            leading=15,
            textColor=TEXT,
            spaceAfter=5,
        ),
        "hunt_title": ParagraphStyle(
            "hunt_title",
            fontName="Helvetica-Bold",
            fontSize=13,
            leading=17,
            textColor=TEXT,
            spaceAfter=5,
        ),
        "query_title": ParagraphStyle(
            "query_title",
            fontName="Helvetica-Bold",
            fontSize=9,
            leading=12,
            textColor=ACCENT,
            spaceAfter=4,
        ),
        "query": ParagraphStyle(
            "query",
            fontName="Courier",
            fontSize=6.5,
            leading=9,
            textColor=TEXT,
            wordWrap="CJK",
        ),
        "context_title": ParagraphStyle(
            "context_title",
            fontName="Helvetica-Bold",
            fontSize=10,
            leading=14,
            textColor=TEXT,
        ),
        "body": ParagraphStyle(
            "body",
            fontName="Helvetica",
            fontSize=8.5,
            leading=12,
            textColor=TEXT,
        ),
        "muted": ParagraphStyle(
            "muted",
            fontName="Helvetica",
            fontSize=8,
            leading=11,
            textColor=MUTED,
        ),
        "small": ParagraphStyle(
            "small",
            fontName="Helvetica",
            fontSize=7,
            leading=9,
            textColor=MUTED,
        ),
        "label": ParagraphStyle(
            "label",
            fontName="Helvetica-Bold",
            fontSize=7,
            leading=9,
            textColor=ACCENT,
            spaceAfter=2,
        ),
        "metric_number": ParagraphStyle(
            "metric_number",
            fontName="Helvetica-Bold",
            fontSize=19,
            leading=21,
            textColor=TEXT,
            alignment=TA_CENTER,
        ),
        "metric_label": ParagraphStyle(
            "metric_label",
            fontName="Helvetica-Bold",
            fontSize=7,
            leading=9,
            textColor=MUTED,
            alignment=TA_CENTER,
        ),
        "priority": ParagraphStyle(
            "priority",
            fontName="Helvetica-Bold",
            fontSize=8,
            leading=10,
            textColor=colors.white,
            alignment=TA_CENTER,
        ),
        "review": ParagraphStyle(
            "review",
            fontName="Helvetica-Bold",
            fontSize=8,
            leading=11,
            textColor=MEDIUM,
            alignment=TA_CENTER,
        ),
    }


class ThreatIntelDocument(BaseDocTemplate):

    def __init__(self, filename):
        super().__init__(
            filename,
            pagesize=A4,
            leftMargin=16 * mm,
            rightMargin=16 * mm,
            topMargin=18 * mm,
            bottomMargin=17 * mm,
            title="Threat Intelligence Daily Brief",
            author="ThreatIntel",
        )

        frame = Frame(
            self.leftMargin,
            self.bottomMargin,
            self.width,
            self.height,
            id="main",
            leftPadding=0,
            rightPadding=0,
            topPadding=0,
            bottomPadding=0,
        )

        template = PageTemplate(
            id="dark",
            frames=[frame],
            onPage=self.draw_page,
        )

        self.addPageTemplates(
            [template]
        )

    def draw_page(
        self,
        canvas,
        doc,
    ):
        canvas.saveState()

        canvas.setFillColor(
            BACKGROUND
        )

        canvas.rect(
            0,
            0,
            PAGE_WIDTH,
            PAGE_HEIGHT,
            fill=1,
            stroke=0,
        )

        if doc.page > 1:
            canvas.setStrokeColor(
                BORDER
            )

            canvas.setLineWidth(
                0.5
            )

            canvas.line(
                16 * mm,
                PAGE_HEIGHT - 12 * mm,
                PAGE_WIDTH - 16 * mm,
                PAGE_HEIGHT - 12 * mm,
            )

            canvas.setFillColor(
                MUTED
            )

            canvas.setFont(
                "Helvetica",
                7,
            )

            canvas.drawString(
                16 * mm,
                PAGE_HEIGHT - 9 * mm,
                "THREAT INTELLIGENCE DAILY BRIEF",
            )

            canvas.drawRightString(
                PAGE_WIDTH - 16 * mm,
                9 * mm,
                f"PAGE {doc.page}",
            )

        canvas.restoreState()


def metric_card(
    value,
    label,
    styles,
    accent=None,
):
    number_style = styles[
        "metric_number"
    ]

    if accent is not None:
        number_style = ParagraphStyle(
            f"metric_{label}",
            parent=number_style,
            textColor=accent,
        )

    return [
        Paragraph(
            safe(
                value,
                "0",
            ),
            number_style,
        ),
        Paragraph(
            safe(label),
            styles[
                "metric_label"
            ],
        ),
    ]


def build_metric_table(
    threats,
    styles,
):
    counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "INFORMATIONAL": 0,
    }

    for event in threats:
        level = get_priority(event)

        if level in counts:
            counts[level] += 1

    metrics = [
        (
            counts["CRITICAL"],
            "CRITICAL",
            CRITICAL,
        ),
        (
            counts["HIGH"],
            "HIGH",
            HIGH,
        ),
        (
            counts["MEDIUM"],
            "MEDIUM",
            MEDIUM,
        ),
        (
            counts["INFORMATIONAL"],
            "WATCHLIST",
            INFO,
        ),
    ]

    cells = [
        metric_card(
            value,
            label,
            styles,
            accent,
        )
        for value, label, accent
        in metrics
    ]

    table = Table(
        [cells],
        colWidths=[
            42 * mm
        ] * 4,
    )

    table.setStyle(
        TableStyle(
            [
                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, -1),
                    PANEL,
                ),
                (
                    "BOX",
                    (0, 0),
                    (-1, -1),
                    0.6,
                    BORDER,
                ),
                (
                    "INNERGRID",
                    (0, 0),
                    (-1, -1),
                    0.4,
                    BORDER,
                ),
                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "MIDDLE",
                ),
                (
                    "TOPPADDING",
                    (0, 0),
                    (-1, -1),
                    9,
                ),
                (
                    "BOTTOMPADDING",
                    (0, 0),
                    (-1, -1),
                    9,
                ),
            ]
        )
    )

    return table


def build_secondary_metrics(
    report,
    threats,
    context,
    non_threat,
    styles,
):
    summary = report.get(
        "summary",
        {},
    )

    metrics = [
        (
            len(threats),
            "THREATS",
        ),
        (
            len(context),
            "CONTEXT",
        ),
        (
            len(non_threat),
            "FILTERED",
        ),
        (
            summary.get(
                "cves",
                0,
            ),
            "CVEs",
        ),
        (
            summary.get(
                "kev",
                0,
            ),
            "KEV",
        ),
    ]

    cells = [
        metric_card(
            value,
            label,
            styles,
        )
        for value, label
        in metrics
    ]

    table = Table(
        [cells],
        colWidths=[
            33.6 * mm
        ] * 5,
    )

    table.setStyle(
        TableStyle(
            [
                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, -1),
                    PANEL_ALT,
                ),
                (
                    "BOX",
                    (0, 0),
                    (-1, -1),
                    0.5,
                    BORDER,
                ),
                (
                    "INNERGRID",
                    (0, 0),
                    (-1, -1),
                    0.3,
                    BORDER,
                ),
                (
                    "TOPPADDING",
                    (0, 0),
                    (-1, -1),
                    7,
                ),
                (
                    "BOTTOMPADDING",
                    (0, 0),
                    (-1, -1),
                    7,
                ),
            ]
        )
    )

    return table


def badge(
    text,
    styles,
    background,
    width=28 * mm,
):
    result = Table(
        [
            [
                Paragraph(
                    safe(text),
                    styles[
                        "priority"
                    ],
                )
            ]
        ],
        colWidths=[
            width
        ],
    )

    result.setStyle(
        TableStyle(
            [
                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, -1),
                    background,
                ),
                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "MIDDLE",
                ),
                (
                    "TOPPADDING",
                    (0, 0),
                    (-1, -1),
                    4,
                ),
                (
                    "BOTTOMPADDING",
                    (0, 0),
                    (-1, -1),
                    4,
                ),
            ]
        )
    )

    return result


def labelled_text(
    label,
    value,
    styles,
):
    value = text_value(value)

    if not value:
        return []

    return [
        Paragraph(
            safe(label).upper(),
            styles[
                "label"
            ],
        ),
        Paragraph(
            safe(value),
            styles[
                "body"
            ],
        ),
        Spacer(
            1,
            5,
        ),
    ]


def labelled_list(
    label,
    values,
    styles,
):
    if not values:
        return []

    result = [
        Paragraph(
            safe(label).upper(),
            styles[
                "label"
            ],
        )
    ]

    for value in values:
        if isinstance(value, dict):
            text = text_value(value)

        else:
            text = clean_inline_text(
                str(value)
            )

        if not text:
            continue

        result.append(
            Paragraph(
                "&#8226; "
                + safe(text),
                styles[
                    "body"
                ],
            )
        )

        result.append(
            Spacer(
                1,
                2,
            )
        )

    result.append(
        Spacer(
            1,
            4,
        )
    )

    return result


def build_customer_relevance(
    event,
    styles,
):
    exposure = get_customer_exposure(event)

    if not exposure:
        return []

    relevant = bool(
        exposure.get(
            "relevant",
            False,
        )
    )

    if not relevant:
        return []

    technologies = get_customer_technologies(event)

    level = (
        exposure.get(
            "match_level"
        )
        or exposure.get(
            "level"
        )
        or exposure.get(
            "highest_match_level"
        )
        or "MATCHED"
    )

    body = [
        Paragraph(
            "MANAGED CUSTOMER ESTATE RELEVANCE",
            styles[
                "label"
            ],
        ),
        Paragraph(
            (
                "<b>Potentially relevant to the "
                "managed technology estate.</b>"
            ),
            styles[
                "body"
            ],
        ),
    ]

    if technologies:
        body.extend(
            [
                Spacer(
                    1,
                    3,
                ),
                Paragraph(
                    (
                        "<b>Matched technologies:</b> "
                        + safe(
                            ", ".join(
                                technologies
                            )
                        )
                    ),
                    styles[
                        "body"
                    ],
                ),
            ]
        )

    body.extend(
        [
            Spacer(
                1,
                3,
            ),
            Paragraph(
                (
                    "<b>Match level:</b> "
                    + safe(level)
                ),
                styles[
                    "small"
                ],
            ),
            Spacer(
                1,
                3,
            ),
            Paragraph(
                (
                    "Technology relevance does not "
                    "confirm vulnerability, exposure, "
                    "exploitation or compromise. "
                    "Product version, patch state, "
                    "configuration and exposure must "
                    "be validated."
                ),
                styles[
                    "small"
                ],
            ),
        ]
    )

    table = Table(
        [
            [body]
        ],
        colWidths=[
            164 * mm
        ],
    )

    table.setStyle(
        TableStyle(
            [
                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, -1),
                    PANEL_ALT,
                ),
                (
                    "BOX",
                    (0, 0),
                    (-1, -1),
                    0.8,
                    CUSTOMER,
                ),
                (
                    "LEFTPADDING",
                    (0, 0),
                    (-1, -1),
                    7,
                ),
                (
                    "RIGHTPADDING",
                    (0, 0),
                    (-1, -1),
                    7,
                ),
                (
                    "TOPPADDING",
                    (0, 0),
                    (-1, -1),
                    7,
                ),
                (
                    "BOTTOMPADDING",
                    (0, 0),
                    (-1, -1),
                    7,
                ),
            ]
        )
    )

    return [
        table,
        Spacer(
            1,
            6,
        ),
    ]


def build_event_card(
    event,
    styles,
):
    priority = event.get(
        "priority",
        {},
    ) or {}

    level = get_priority(event)

    score = priority.get(
        "score",
        0,
    )

    title = event.get(
        "title",
        "Untitled threat event",
    )

    cves = event.get(
        "cves",
        [],
    ) or []

    kev = event.get(
        "kev",
        [],
    ) or []

    source_names = get_source_names(event)

    heading = Table(
        [
            [
                badge(
                    level,
                    styles,
                    priority_color(
                        level
                    ),
                ),
                Paragraph(
                    safe(title),
                    styles[
                        "event_title"
                    ],
                ),
            ]
        ],
        colWidths=[
            31 * mm,
            137 * mm,
        ],
    )

    heading.setStyle(
        TableStyle(
            [
                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "TOP",
                ),
                (
                    "LEFTPADDING",
                    (0, 0),
                    (-1, -1),
                    0,
                ),
                (
                    "RIGHTPADDING",
                    (0, 0),
                    (-1, -1),
                    5,
                ),
                (
                    "TOPPADDING",
                    (0, 0),
                    (-1, -1),
                    0,
                ),
                (
                    "BOTTOMPADDING",
                    (0, 0),
                    (-1, -1),
                    0,
                ),
            ]
        )
    )

    metadata = (
        f"Priority score: {score}"
        f"   |   Confidence: "
        f"{get_confidence(event)}"
        f"   |   CVEs: {len(cves)}"
        f"   |   KEV: {len(kev)}"
        f"   |   Candidate IOCs: "
        f"{get_candidate_iocs(event)}"
    )

    if customer_relevant(event):
        metadata += (
            "   |   Managed estate: RELEVANT"
        )

    if source_names:
        metadata += (
            "   |   Sources: "
            + ", ".join(
                source_names[:4]
            )
        )

    body = [
        heading,
        Spacer(
            1,
            4,
        ),
        Paragraph(
            safe(metadata),
            styles[
                "small"
            ],
        ),
        Spacer(
            1,
            7,
        ),
    ]

    body.extend(
        build_customer_relevance(
            event,
            styles,
        )
    )

    body.extend(
        labelled_text(
            "Executive Summary",
            get_summary(event),
            styles,
        )
    )

    body.extend(
        labelled_text(
            "What Is It?",
            get_what_is_it(event),
            styles,
        )
    )

    body.extend(
        labelled_text(
            "Affected Technologies",
            get_affected_technologies(
                event
            ),
            styles,
        )
    )

    body.extend(
        labelled_text(
            "Exploitation Status",
            get_exploitation(event),
            styles,
        )
    )

    body.extend(
        labelled_text(
            "Potential Impact",
            get_potential_impact(
                event
            ),
            styles,
        )
    )

    if cves:
        body.extend(
            labelled_text(
                "Vulnerabilities",
                ", ".join(
                    str(cve)
                    for cve in cves[:20]
                ),
                styles,
            )
        )

    body.extend(
        labelled_text(
            "Recommended Actions",
            get_actions(event),
            styles,
        )
    )

    body.extend(
        labelled_text(
            "Intelligence Gaps",
            get_intelligence_gaps(
                event
            ),
            styles,
        )
    )

    container = Table(
        [
            [body]
        ],
        colWidths=[
            168 * mm
        ],
    )

    container.setStyle(
        TableStyle(
            [
                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, -1),
                    PANEL,
                ),
                (
                    "BOX",
                    (0, 0),
                    (-1, -1),
                    0.6,
                    BORDER,
                ),
                (
                    "LEFTPADDING",
                    (0, 0),
                    (-1, -1),
                    8,
                ),
                (
                    "RIGHTPADDING",
                    (0, 0),
                    (-1, -1),
                    8,
                ),
                (
                    "TOPPADDING",
                    (0, 0),
                    (-1, -1),
                    8,
                ),
                (
                    "BOTTOMPADDING",
                    (0, 0),
                    (-1, -1),
                    8,
                ),
            ]
        )
    )

    return [
        container,
        Spacer(
            1,
            7,
        ),
    ]


def build_context_card(
    event,
    styles,
):
    title = event.get(
        "title",
        "Untitled context item",
    )

    source_names = get_source_names(event)

    body = [
        Paragraph(
            safe(title),
            styles[
                "context_title"
            ],
        ),
        Spacer(
            1,
            4,
        ),
        Paragraph(
            safe(
                get_summary(event)
            ),
            styles[
                "muted"
            ],
        ),
    ]

    if source_names:
        body.extend(
            [
                Spacer(
                    1,
                    4,
                ),
                Paragraph(
                    (
                        "<b>Sources:</b> "
                        + safe(
                            ", ".join(
                                source_names[:4]
                            )
                        )
                    ),
                    styles[
                        "small"
                    ],
                ),
            ]
        )

    container = Table(
        [
            [
                badge(
                    "CONTEXT",
                    styles,
                    CONTEXT,
                    width=25 * mm,
                ),
                body,
            ]
        ],
        colWidths=[
            29 * mm,
            139 * mm,
        ],
    )

    container.setStyle(
        TableStyle(
            [
                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, -1),
                    PANEL_ALT,
                ),
                (
                    "BOX",
                    (0, 0),
                    (-1, -1),
                    0.5,
                    BORDER,
                ),
                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "TOP",
                ),
                (
                    "LEFTPADDING",
                    (0, 0),
                    (-1, -1),
                    7,
                ),
                (
                    "RIGHTPADDING",
                    (0, 0),
                    (-1, -1),
                    7,
                ),
                (
                    "TOPPADDING",
                    (0, 0),
                    (-1, -1),
                    7,
                ),
                (
                    "BOTTOMPADDING",
                    (0, 0),
                    (-1, -1),
                    7,
                ),
            ]
        )
    )

    return KeepTogether(
        [
            container,
            Spacer(
                1,
                6,
            ),
        ]
    )


def build_attack_chain(
    attack_chain,
    styles,
):
    if not attack_chain:
        return []

    result = [
        Paragraph(
            "ATTACK CHAIN",
            styles[
                "label"
            ],
        )
    ]

    for item in attack_chain:
        if not isinstance(item, dict):
            continue

        stage = item.get(
            "stage",
            "Stage",
        )

        activity = item.get(
            "activity",
            "",
        )

        evidence = item.get(
            "evidence_basis",
            "",
        )

        result.append(
            Paragraph(
                (
                    f"<b>{safe(stage)}:</b> "
                    f"{safe(activity)}"
                ),
                styles[
                    "body"
                ],
            )
        )

        if evidence:
            result.append(
                Paragraph(
                    (
                        "<b>Evidence basis:</b> "
                        + safe(evidence)
                    ),
                    styles[
                        "small"
                    ],
                )
            )

        result.append(
            Spacer(
                1,
                4,
            )
        )

    return result


def build_query_panel(
    title,
    section,
    styles,
):
    if not isinstance(section, dict):
        return []

    status = section.get(
        "status",
        "REVIEW BEFORE DEPLOYMENT",
    )

    query = section.get(
        "query",
        "",
    )

    looks_for = section.get(
        "what_it_looks_for",
        "",
    )

    notes = section.get(
        "environment_notes",
        [],
    ) or []

    # Only the short heading is kept in a table.
    # The query itself remains a splittable Paragraph,
    # allowing a long hunt to continue across pages.
    heading = Table(
        [
            [
                Paragraph(
                    safe(title),
                    styles[
                        "query_title"
                    ],
                ),
                Paragraph(
                    safe(status),
                    styles[
                        "review"
                    ],
                ),
            ]
        ],
        colWidths=[
            108 * mm,
            56 * mm,
        ],
    )

    heading.setStyle(
        TableStyle(
            [
                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, -1),
                    PANEL_ALT,
                ),
                (
                    "BOX",
                    (0, 0),
                    (-1, -1),
                    0.6,
                    BORDER,
                ),
                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "MIDDLE",
                ),
                (
                    "LEFTPADDING",
                    (0, 0),
                    (-1, -1),
                    7,
                ),
                (
                    "RIGHTPADDING",
                    (0, 0),
                    (-1, -1),
                    7,
                ),
                (
                    "TOPPADDING",
                    (0, 0),
                    (-1, -1),
                    6,
                ),
                (
                    "BOTTOMPADDING",
                    (0, 0),
                    (-1, -1),
                    6,
                ),
            ]
        )
    )

    result = [
        heading,
        Spacer(
            1,
            5,
        ),
    ]

    if query:
        query_style = ParagraphStyle(
            "query_box",
            parent=styles[
                "query"
            ],
            backColor=BACKGROUND,
            borderColor=BORDER,
            borderWidth=0.5,
            borderPadding=6,
            spaceBefore=0,
            spaceAfter=5,
        )

        result.append(
            Paragraph(
                safe(query),
                query_style,
            )
        )

        result.append(
            Spacer(
                1,
                3,
            )
        )

    if looks_for:
        result.extend(
            labelled_text(
                "What This Hunt Looks For",
                looks_for,
                styles,
            )
        )

    if notes:
        result.extend(
            labelled_list(
                "Environment / Deployment Notes",
                notes,
                styles,
            )
        )

    result.append(
        Spacer(
            1,
            4,
        )
    )

    return result


def build_source_intelligence(
    sources,
    styles,
):
    if not sources:
        return []

    result = [
        Paragraph(
            "SOURCE INTELLIGENCE",
            styles[
                "label"
            ],
        )
    ]

    for source in sources:
        if not isinstance(source, dict):
            continue

        publisher = source.get(
            "source",
            "Unknown source",
        )

        title = source.get(
            "title",
            "",
        )

        url = source.get(
            "url",
            "",
        )

        line = (
            f"<b>{safe(publisher)}</b>"
        )

        if title:
            line += (
                " - "
                + safe(title)
            )

        result.append(
            Paragraph(
                line,
                styles[
                    "body"
                ],
            )
        )

        if url:
            result.append(
                Paragraph(
                    safe(url),
                    styles[
                        "small"
                    ],
                )
            )

        result.append(
            Spacer(
                1,
                4,
            )
        )

    return result


def build_hunt_pack(
    wrapper,
    number,
    styles,
):
    pack = (
        wrapper.get(
            "hunt_pack"
        )
        or {}
    )

    selection = (
        wrapper.get(
            "selection"
        )
        or {}
    )

    title = (
        pack.get(
            "title"
        )
        or wrapper.get(
            "event_title"
        )
        or f"Threat Hunt {number}"
    )

    confidence = pack.get(
        "confidence",
        "UNKNOWN",
    )

    hunt_score = selection.get(
        "score",
        "Unknown",
    )

    behaviours = selection.get(
        "behaviours",
        [],
    ) or []

    behaviour_names = []

    for behaviour in behaviours:
        if isinstance(
            behaviour,
            dict,
        ):
            name = behaviour.get(
                "name"
            )

            if name:
                behaviour_names.append(
                    str(name)
                )

        elif behaviour:
            behaviour_names.append(
                str(behaviour)
            )

    telemetry = (
        selection.get(
            "telemetry",
            [],
        )
        or pack.get(
            "expected_telemetry",
            [],
        )
        or []
    )

    validation = (
        pack.get(
            "validation"
        )
        or {}
    )

    validated = bool(
        validation.get(
            "passed",
            False,
        )
    )

    if validated:
        validation_text = (
            "LOCAL VALIDATION PASSED"
        )

        validation_color = SUCCESS

    else:
        validation_text = (
            "VALIDATION REVIEW REQUIRED"
        )

        validation_color = MEDIUM

    # Only the compact hunt heading lives in a table.
    # The detailed content below remains splittable.
    header = [
        Paragraph(
            f"THREAT HUNT {number}",
            styles[
                "label"
            ],
        ),
        Paragraph(
            safe(title),
            styles[
                "hunt_title"
            ],
        ),
        Paragraph(
            (
                f"Huntability score: "
                f"{safe(hunt_score)}"
                f"   |   Confidence: "
                f"{safe(confidence)}"
            ),
            styles[
                "small"
            ],
        ),
        Spacer(
            1,
            5,
        ),
        badge(
            validation_text,
            styles,
            validation_color,
            width=52 * mm,
        ),
        Spacer(
            1,
            7,
        ),
        Paragraph(
            "REVIEW BEFORE DEPLOYMENT",
            styles[
                "review"
            ],
        ),
    ]

    container = Table(
        [
            [header]
        ],
        colWidths=[
            168 * mm
        ],
    )

    container.setStyle(
        TableStyle(
            [
                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, -1),
                    PANEL,
                ),
                (
                    "BOX",
                    (0, 0),
                    (-1, -1),
                    0.8,
                    ACCENT,
                ),
                (
                    "LEFTPADDING",
                    (0, 0),
                    (-1, -1),
                    8,
                ),
                (
                    "RIGHTPADDING",
                    (0, 0),
                    (-1, -1),
                    8,
                ),
                (
                    "TOPPADDING",
                    (0, 0),
                    (-1, -1),
                    8,
                ),
                (
                    "BOTTOMPADDING",
                    (0, 0),
                    (-1, -1),
                    8,
                ),
            ]
        )
    )

    result = [
        container,
        Spacer(
            1,
            8,
        ),
    ]

    managed = (
        pack.get(
            "managed_estate_relevance"
        )
        or {}
    )

    if managed:
        relevant = bool(
            managed.get(
                "relevant",
                False,
            )
        )

        technologies = (
            managed.get(
                "technologies",
                [],
            )
            or []
        )

        assessment = managed.get(
            "assessment",
            "",
        )

        managed_text = (
            "Potentially relevant"
            if relevant
            else
            "No managed-estate product match recorded"
        )

        result.extend(
            labelled_text(
                "Customer Technology Relevance",
                managed_text,
                styles,
            )
        )

        if technologies:
            result.extend(
                labelled_text(
                    "Matched Managed Technologies",
                    ", ".join(
                        str(value)
                        for value
                        in technologies
                    ),
                    styles,
                )
            )

        if assessment:
            result.extend(
                labelled_text(
                    "Estate Assessment",
                    assessment,
                    styles,
                )
            )

    result.extend(
        labelled_text(
            "Hypothesis",
            pack.get(
                "hypothesis"
            ),
            styles,
        )
    )

    result.extend(
        labelled_list(
            "Why This Hunt Was Selected",
            pack.get(
                "why_selected",
                [],
            ),
            styles,
        )
    )

    result.extend(
        labelled_list(
            "Threat Characteristics",
            pack.get(
                "threat_characteristics",
                [],
            ),
            styles,
        )
    )

    result.extend(
        build_attack_chain(
            pack.get(
                "attack_chain",
                [],
            ),
            styles,
        )
    )

    if behaviour_names:
        result.extend(
            labelled_text(
                "Detected Hunt Behaviours",
                ", ".join(
                    behaviour_names
                ),
                styles,
            )
        )

    if telemetry:
        result.extend(
            labelled_list(
                "Expected Telemetry",
                telemetry,
                styles,
            )
        )

    result.append(
        Spacer(
            1,
            4,
        )
    )

    result.extend(
        build_query_panel(
            "GOOGLE SECOPS - UDM HUNT",
            pack.get(
                "google_secops_udm",
                {},
            ),
            styles,
        )
    )

    result.extend(
        build_query_panel(
            (
                "MICROSOFT DEFENDER XDR - "
                "KQL ADVANCED HUNTING"
            ),
            pack.get(
                "microsoft_defender_kql",
                {},
            ),
            styles,
        )
    )

    result.extend(
        build_query_panel(
            "CORTEX XDR - XQL HUNT",
            pack.get(
                "cortex_xdr_xql",
                {},
            ),
            styles,
        )
    )

    result.extend(
        labelled_list(
            "Why Suspicious",
            pack.get(
                "why_suspicious",
                [],
            ),
            styles,
        )
    )

    result.extend(
        labelled_list(
            "Potential False Positives",
            pack.get(
                "potential_false_positives",
                [],
            ),
            styles,
        )
    )

    result.extend(
        labelled_list(
            "Analyst Validation",
            pack.get(
                "analyst_validation",
                [],
            ),
            styles,
        )
    )

    result.extend(
        labelled_list(
            "Intelligence Gaps",
            pack.get(
                "intelligence_gaps",
                [],
            ),
            styles,
        )
    )

    result.extend(
        build_source_intelligence(
            pack.get(
                "source_intelligence",
                [],
            ),
            styles,
        )
    )

    result.extend(
        labelled_text(
            "Confidence",
            pack.get(
                "confidence"
            ),
            styles,
        )
    )

    result.extend(
        labelled_text(
            "Confidence Rationale",
            pack.get(
                "confidence_reason"
            ),
            styles,
        )
    )

    problems = validation.get(
        "problems",
        [],
    ) or []

    if problems:
        result.extend(
            labelled_list(
                "Local Validation Problems",
                problems,
                styles,
            )
        )

    result.append(
        Spacer(
            1,
            8 * mm,
        )
    )

    return result


def build_pdf(
    report,
    output_path,
):
    output_path = Path(
        output_path
    )

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    styles = build_styles()

    metadata = report.get(
        "metadata",
        {},
    )

    events = report.get(
        "events",
        [],
    ) or []

    hunt_packs = report.get(
        "threat_hunts",
        [],
    ) or []

    (
        threats,
        context,
        non_threat,
    ) = split_events(events)

    generated_at = metadata.get(
        "generated_at",
        "",
    )

    try:
        generated_date = (
            datetime.fromisoformat(
                generated_at
            )
            .strftime(
                "%d %B %Y"
            )
            .upper()
        )

    except (
        TypeError,
        ValueError,
    ):
        generated_date = (
            "CURRENT REPORTING PERIOD"
        )

    story = []

    # COVER

    story.append(
        Spacer(
            1,
            28 * mm,
        )
    )

    story.append(
        Paragraph(
            "DEFENSIVE CYBER THREAT INTELLIGENCE",
            styles[
                "cover_label"
            ],
        )
    )

    story.append(
        Paragraph(
            "THREAT INTELLIGENCE<br/>"
            "DAILY BRIEF",
            styles[
                "cover_title"
            ],
        )
    )

    story.append(
        Paragraph(
            safe(generated_date),
            styles[
                "cover_subtitle"
            ],
        )
    )

    story.append(
        Spacer(
            1,
            16 * mm,
        )
    )

    story.append(
        build_metric_table(
            threats,
            styles,
        )
    )

    story.append(
        Spacer(
            1,
            6 * mm,
        )
    )

    story.append(
        build_secondary_metrics(
            report,
            threats,
            context,
            non_threat,
            styles,
        )
    )

    story.append(
        Spacer(
            1,
            10 * mm,
        )
    )

    if hunt_packs:
        hunt_metric = Table(
            [
                [
                    metric_card(
                        len(hunt_packs),
                        "THREAT HUNTS",
                        styles,
                        ACCENT,
                    ),
                    metric_card(
                        sum(
                            1
                            for event
                            in threats
                            if customer_relevant(
                                event
                            )
                        ),
                        "ESTATE RELEVANT",
                        styles,
                        CUSTOMER,
                    ),
                ]
            ],
            colWidths=[
                84 * mm,
                84 * mm,
            ],
        )

        hunt_metric.setStyle(
            TableStyle(
                [
                    (
                        "BACKGROUND",
                        (0, 0),
                        (-1, -1),
                        PANEL,
                    ),
                    (
                        "BOX",
                        (0, 0),
                        (-1, -1),
                        0.5,
                        BORDER,
                    ),
                    (
                        "INNERGRID",
                        (0, 0),
                        (-1, -1),
                        0.3,
                        BORDER,
                    ),
                    (
                        "TOPPADDING",
                        (0, 0),
                        (-1, -1),
                        7,
                    ),
                    (
                        "BOTTOMPADDING",
                        (0, 0),
                        (-1, -1),
                        7,
                    ),
                ]
            )
        )

        story.append(hunt_metric)

        story.append(
            Spacer(
                1,
                8 * mm,
            )
        )

    story.append(
        HRFlowable(
            width="100%",
            thickness=0.7,
            color=BORDER,
        )
    )

    story.append(
        Spacer(
            1,
            6 * mm,
        )
    )

    story.append(
        Paragraph(
            (
                f"Coverage window: "
                f"{safe(metadata.get('collection_hours', 24))} hours"
                f"<br/>"
                f"Reports collected: "
                f"{safe(metadata.get('reports_collected', 0))}"
                f"<br/>"
                f"Correlated events: "
                f"{safe(len(events))}"
                f"<br/>"
                f"Source failures: "
                f"{safe(metadata.get('source_failures', 0))}"
                f"<br/>"
                f"Managed-estate relevant threats: "
                f"{safe(sum(1 for event in threats if customer_relevant(event)))}"
                f"<br/>"
                f"Threat hunt packs: "
                f"{safe(len(hunt_packs))}"
                f"<br/>"
                f"Filtered non-threat content: "
                f"{safe(len(non_threat))}"
            ),
            styles[
                "muted"
            ],
        )
    )

    # EXECUTIVE LANDSCAPE

    story.append(
        PageBreak()
    )

    story.append(
        Paragraph(
            "EXECUTIVE THREAT LANDSCAPE",
            styles[
                "section"
            ],
        )
    )

    estate_count = sum(
        1
        for event in threats
        if customer_relevant(event)
    )

    story.append(
        Paragraph(
            (
                f"{len(threats)} operational threat events "
                f"were identified in the reporting window. "
                f"{estate_count} operational threat event(s) "
                f"matched technologies represented in the "
                f"managed customer estate. "
                f"{len(context)} additional items were retained "
                f"as security context. "
                f"{len(non_threat)} non-threat items were filtered "
                f"from the report body."
            ),
            styles[
                "body"
            ],
        )
    )

    story.append(
        Spacer(
            1,
            6 * mm,
        )
    )

    story.append(
        Paragraph(
            "TOP OPERATIONAL EVENTS",
            styles[
                "label"
            ],
        )
    )

    for event in threats[:5]:
        level = get_priority(event)

        title = event.get(
            "title",
            "Untitled event",
        )

        estate = (
            " | MANAGED ESTATE RELEVANT"
            if customer_relevant(event)
            else ""
        )

        story.append(
            Paragraph(
                (
                    f"<b>{safe(level)}</b> - "
                    f"{safe(title)}"
                    f"{safe(estate, '')}"
                ),
                styles[
                    "body"
                ],
            )
        )

        story.append(
            Spacer(
                1,
                2 * mm,
            )
        )

    # OPERATIONAL THREATS

    story.append(
        Spacer(
            1,
            8 * mm,
        )
    )

    story.append(
        Paragraph(
            "OPERATIONAL THREAT EVENTS",
            styles[
                "section"
            ],
        )
    )

    story.append(
        Paragraph(
            (
                "Events below contain operational threat evidence "
                "and are ordered by deterministic priority. "
                "Priority, analytical confidence and managed-estate "
                "relevance are separate concepts. A technology match "
                "does not establish customer exposure or compromise."
            ),
            styles[
                "section_note"
            ],
        )
    )

    if threats:
        for event in threats:
            story.extend(
                build_event_card(
                    event,
                    styles,
                )
            )

    else:
        story.append(
            Paragraph(
                (
                    "No operational threat events were identified "
                    "during this reporting period."
                ),
                styles[
                    "body"
                ],
            )
        )

    # THREAT HUNTING PACK

    if hunt_packs:
        story.append(
            PageBreak()
        )

        story.append(
            Paragraph(
                "THREAT HUNTING PACK",
                styles[
                    "section"
                ],
            )
        )

        story.append(
            Paragraph(
                (
                    f"{len(hunt_packs)} evidence-grounded hunt "
                    f"pack(s) were selected from current operational "
                    f"threat intelligence. Selection is based on "
                    f"observable attacker behaviour, available "
                    f"telemetry, operational priority and managed-"
                    f"estate relevance. Huntability is independent "
                    f"from vulnerability priority."
                ),
                styles[
                    "body"
                ],
            )
        )

        story.append(
            Spacer(
                1,
                4 * mm,
            )
        )

        review_box = Table(
            [
                [
                    Paragraph(
                        (
                            "ALL HUNT QUERIES ARE "
                            "REVIEW BEFORE DEPLOYMENT"
                        ),
                        styles[
                            "review"
                        ],
                    )
                ]
            ],
            colWidths=[
                168 * mm
            ],
        )

        review_box.setStyle(
            TableStyle(
                [
                    (
                        "BACKGROUND",
                        (0, 0),
                        (-1, -1),
                        PANEL_ALT,
                    ),
                    (
                        "BOX",
                        (0, 0),
                        (-1, -1),
                        0.8,
                        MEDIUM,
                    ),
                    (
                        "TOPPADDING",
                        (0, 0),
                        (-1, -1),
                        7,
                    ),
                    (
                        "BOTTOMPADDING",
                        (0, 0),
                        (-1, -1),
                        7,
                    ),
                ]
            )
        )

        story.append(review_box)

        story.append(
            Spacer(
                1,
                7 * mm,
            )
        )

        story.append(
            Paragraph(
                (
                    "Queries are analyst starting points and must "
                    "be validated against local schemas, field "
                    "availability, retention, telemetry coverage "
                    "and expected environmental noise. They are "
                    "not automatically deployed as detections or "
                    "blocking controls."
                ),
                styles[
                    "section_note"
                ],
            )
        )

        for number, wrapper in enumerate(
            hunt_packs,
            start=1,
        ):
            if number > 1:
                story.append(
                    PageBreak()
                )

            story.extend(
                build_hunt_pack(
                    wrapper,
                    number,
                    styles,
                )
            )

    # SECURITY CONTEXT

    if context:
        story.append(
            PageBreak()
        )

        story.append(
            Paragraph(
                "SECURITY CONTEXT",
                styles[
                    "section"
                ],
            )
        )

        story.append(
            Paragraph(
                (
                    "Relevant cybersecurity developments that do "
                    "not currently meet the operational-threat "
                    "classification threshold. These items are "
                    "retained for situational awareness."
                ),
                styles[
                    "section_note"
                ],
            )
        )

        for event in context:
            story.append(
                build_context_card(
                    event,
                    styles,
                )
            )

    # REPORT NOTES

    story.append(
        PageBreak()
    )

    story.append(
        Paragraph(
            "REPORT NOTES",
            styles[
                "section"
            ],
        )
    )

    story.append(
        Paragraph(
            (
                "<b>Operational threat:</b> reporting containing "
                "structured or textual evidence of vulnerabilities, "
                "exploitation, malware, ransomware, phishing, "
                "breaches, compromise, attack paths or related "
                "defensive intelligence."
            ),
            styles[
                "body"
            ],
        )
    )

    story.append(
        Spacer(
            1,
            4 * mm,
        )
    )

    story.append(
        Paragraph(
            (
                "<b>Managed customer estate relevance:</b> "
                "technology correlation indicates that a product "
                "or technology represented in the combined managed "
                "estate appears relevant to the intelligence. "
                "This does not confirm that a customer is vulnerable, "
                "exposed, exploited or compromised."
            ),
            styles[
                "body"
            ],
        )
    )

    story.append(
        Spacer(
            1,
            4 * mm,
        )
    )

    story.append(
        Paragraph(
            (
                "<b>Threat hunts:</b> hunt packs are generated only "
                "for selected operational threat events containing "
                "observable behaviour considered suitable for "
                "investigation. A maximum of three hunt packs is "
                "included per run. The system does not force three "
                "hunts when the evidence does not support them."
            ),
            styles[
                "body"
            ],
        )
    )

    story.append(
        Spacer(
            1,
            4 * mm,
        )
    )

    story.append(
        Paragraph(
            (
                "<b>Hunt query safety:</b> Google SecOps UDM, "
                "Microsoft Defender XDR KQL and Cortex XDR XQL "
                "content is marked REVIEW BEFORE DEPLOYMENT. "
                "Queries require analyst validation against the "
                "local environment and are not automatically "
                "deployed as detections."
            ),
            styles[
                "body"
            ],
        )
    )

    story.append(
        Spacer(
            1,
            4 * mm,
        )
    )

    story.append(
        Paragraph(
            (
                "<b>Security context:</b> relevant developments "
                "retained for situational awareness but not treated "
                "as immediate operational threat events."
            ),
            styles[
                "body"
            ],
        )
    )

    story.append(
        Spacer(
            1,
            4 * mm,
        )
    )

    story.append(
        Paragraph(
            (
                "<b>Filtered content:</b> "
                f"{safe(len(non_threat))} item(s) classified as "
                "non-threat content were retained in the underlying "
                "JSON dataset but excluded from this PDF body."
            ),
            styles[
                "body"
            ],
        )
    )

    story.append(
        Spacer(
            1,
            4 * mm,
        )
    )

    story.append(
        Paragraph(
            (
                "<b>IOC handling:</b> candidate indicators are not "
                "automatically treated as confirmed malicious "
                "indicators. Analyst validation remains required "
                "before blocking or other disruptive action."
            ),
            styles[
                "body"
            ],
        )
    )

    document = ThreatIntelDocument(
        str(output_path)
    )

    document.build(story)