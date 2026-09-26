import os


# ============================================================
# COLLECTION
# ============================================================

COLLECTION_HOURS = int(
    os.getenv(
        "COLLECTION_HOURS",
        "24",
    )
)


# ============================================================
# AI ENRICHMENT
# ============================================================

AI_MAX_EVENTS_PER_RUN = int(
    os.getenv(
        "AI_MAX_EVENTS_PER_RUN",
        "0",
    )
)


AI_MIN_PRIORITY = os.getenv(
    "AI_MIN_PRIORITY",
    "MEDIUM",
).upper()


AI_MAX_TOTAL_TOKENS_PER_RUN = int(
    os.getenv(
        "AI_MAX_TOTAL_TOKENS_PER_RUN",
        "120000",
    )
)


PRIORITY_ORDER = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "INFORMATIONAL": 1,
}


VALID_PRIORITIES = set(
    PRIORITY_ORDER
)


def get_event_priority(event):
    return (
        event.get(
            "priority",
            {},
        )
        .get(
            "level",
            "INFORMATIONAL",
        )
        .upper()
    )


def get_event_relevance(event):
    """
    Return the deterministic relevance classification.

    Older/test records without relevance data default to
    CONTEXT so existing callers remain compatible.
    """

    return (
        event.get(
            "relevance",
            {},
        )
        .get(
            "classification",
            "CONTEXT",
        )
        .upper()
    )


def is_ai_eligible(event):
    if "processing_error" in event:
        return False

    #
    # Promotional, event, funding and other explicitly
    # non-threat material must never consume AI tokens.
    #
    if (
        get_event_relevance(event)
        == "NON_THREAT"
    ):
        return False

    priority = get_event_priority(
        event
    )

    minimum = AI_MIN_PRIORITY

    if minimum not in VALID_PRIORITIES:
        minimum = "MEDIUM"

    event_rank = PRIORITY_ORDER.get(
        priority,
        1,
    )

    minimum_rank = PRIORITY_ORDER.get(
        minimum,
        2,
    )

    return (
        event_rank
        >= minimum_rank
    )


def select_events_for_ai(events):
    eligible = [
        event
        for event in events
        if is_ai_eligible(event)
    ]

    eligible.sort(
        key=lambda event: (
            PRIORITY_ORDER.get(
                get_event_priority(
                    event
                ),
                1,
            ),
            event.get(
                "priority",
                {},
            ).get(
                "score",
                0,
            ),
        ),
        reverse=True,
    )

    if AI_MAX_EVENTS_PER_RUN <= 0:
        return eligible

    return eligible[
        :AI_MAX_EVENTS_PER_RUN
    ]


class AIRunBudget:
    """
    Tracks AI token consumption for one application run.

    Tokens are tracked rather than monetary cost because
    provider/model pricing can change independently from
    the application.
    """

    def __init__(
        self,
        max_total_tokens=None,
    ):
        if max_total_tokens is None:
            max_total_tokens = (
                AI_MAX_TOTAL_TOKENS_PER_RUN
            )

        self.max_total_tokens = max(
            0,
            int(max_total_tokens),
        )

        self.input_tokens = 0
        self.output_tokens = 0
        self.total_tokens = 0
        self.completed_calls = 0
        self.failed_calls = 0
        self.skipped_calls = 0

    def can_continue(self):
        if self.max_total_tokens == 0:
            return True

        return (
            self.total_tokens
            < self.max_total_tokens
        )

    def record_usage(
        self,
        usage,
    ):
        usage = usage or {}

        input_tokens = int(
            usage.get(
                "input_tokens",
                0,
            )
            or 0
        )

        output_tokens = int(
            usage.get(
                "output_tokens",
                0,
            )
            or 0
        )

        total_tokens = int(
            usage.get(
                "total_tokens",
                (
                    input_tokens
                    + output_tokens
                ),
            )
            or 0
        )

        self.input_tokens += (
            input_tokens
        )

        self.output_tokens += (
            output_tokens
        )

        self.total_tokens += (
            total_tokens
        )

        self.completed_calls += 1

    def record_failure(self):
        self.failed_calls += 1

    def record_skip(self):
        self.skipped_calls += 1

    def summary(self):
        return {
            "input_tokens": (
                self.input_tokens
            ),
            "output_tokens": (
                self.output_tokens
            ),
            "total_tokens": (
                self.total_tokens
            ),
            "completed_calls": (
                self.completed_calls
            ),
            "failed_calls": (
                self.failed_calls
            ),
            "skipped_calls": (
                self.skipped_calls
            ),
            "token_limit": (
                self.max_total_tokens
            ),
            "limit_reached": (
                not self.can_continue()
            ),
        }