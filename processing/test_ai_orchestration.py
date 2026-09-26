from unittest.mock import patch

import threatintel


def make_event(title, level, score):
    return {
        "title": title,
        "priority": {
            "level": level,
            "score": score,
        },
    }


events = [
    make_event(
        "Critical Event",
        "CRITICAL",
        65,
    ),
    make_event(
        "High Event",
        "HIGH",
        35,
    ),
    make_event(
        "Medium Event",
        "MEDIUM",
        15,
    ),
]


call_count = 0


def fake_enrich(event):
    global call_count

    call_count += 1

    #
    # First request succeeds but consumes enough
    # tokens to cross our deliberately tiny
    # synthetic test budget.
    #
    event["ai_status"] = "success"

    event["ai_usage"] = {
        "input_tokens": 800,
        "output_tokens": 300,
        "total_tokens": 1100,
    }

    event["grounding"] = {
        "passed": True,
        "rejected": [],
        "rejected_count": 0,
        "corrections": [],
        "correction_count": 0,
    }


with patch.object(
    threatintel,
    "AI_MAX_TOTAL_TOKENS_PER_RUN",
    1000,
):
    with patch.object(
        threatintel,
        "enrich_event_with_ai",
        side_effect=fake_enrich,
    ):
        selected, usage = (
            threatintel.run_ai_enrichment(
                events
            )
        )


#
# All three events were eligible.
#
assert len(selected) == 3


#
# Only the first event should actually reach
# our fake AI function.
#
assert call_count == 1, (
    f"Expected 1 AI call, got {call_count}"
)


assert (
    events[0]["ai_status"]
    == "success"
)


assert (
    events[1]["ai_status"]
    == "skipped_budget"
)


assert (
    events[2]["ai_status"]
    == "skipped_budget"
)


assert usage["completed_calls"] == 1
assert usage["skipped_calls"] == 2
assert usage["failed_calls"] == 0
assert usage["total_tokens"] == 1100
assert usage["limit_reached"] is True


print(
    "PASS - eligible events selected"
)

print(
    "PASS - fake AI call executed"
)

print(
    "PASS - token ceiling stopped further calls"
)

print(
    "PASS - remaining events marked skipped"
)

print(
    "PASS - run usage accounting correct"
)


#
# ============================================================
# FAILURE ISOLATION TEST
# ============================================================
#

failure_events = [
    make_event(
        "Failure Event",
        "HIGH",
        35,
    ),
    make_event(
        "Following Event",
        "HIGH",
        35,
    ),
]


failure_call_count = 0


def fake_failure_then_success(event):
    global failure_call_count

    failure_call_count += 1

    if failure_call_count == 1:
        raise RuntimeError(
            "Synthetic AI failure"
        )

    event["ai_status"] = "success"

    event["ai_usage"] = {
        "input_tokens": 100,
        "output_tokens": 50,
        "total_tokens": 150,
    }

    event["grounding"] = {
        "passed": True,
    }


with patch.object(
    threatintel,
    "AI_MAX_TOTAL_TOKENS_PER_RUN",
    10000,
):
    with patch.object(
        threatintel,
        "enrich_event_with_ai",
        side_effect=fake_failure_then_success,
    ):
        _, failure_usage = (
            threatintel.run_ai_enrichment(
                failure_events
            )
        )


assert (
    failure_events[0]["ai_status"]
    == "failed"
)

assert (
    failure_events[1]["ai_status"]
    == "success"
)

assert failure_usage["failed_calls"] == 1
assert failure_usage["completed_calls"] == 1


print(
    "PASS - AI failure did not terminate run"
)

print(
    "PASS - next event processed after failure"
)

print()
print(
    "All AI orchestration tests passed."
)