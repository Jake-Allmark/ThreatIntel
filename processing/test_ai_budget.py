import config


def event(title, level, score):
    return {
        "title": title,
        "priority": {
            "level": level,
            "score": score,
        },
    }


events = [
    event("Informational", "INFORMATIONAL", 0),
    event("Medium", "MEDIUM", 15),
    event("High", "HIGH", 35),
    event("Critical", "CRITICAL", 65),
]


selected = config.select_events_for_ai(events)

titles = [
    item["title"]
    for item in selected
]

assert titles == [
    "Critical",
    "High",
    "Medium",
], titles

print("PASS - production AI selection")


broken = event(
    "Broken",
    "CRITICAL",
    100,
)

broken["processing_error"] = (
    "Synthetic failure"
)

assert not config.is_ai_eligible(
    broken
)

print(
    "PASS - processing failures excluded"
)


budget = config.AIRunBudget(
    max_total_tokens=1000
)

assert budget.can_continue()


budget.record_usage(
    {
        "input_tokens": 400,
        "output_tokens": 100,
        "total_tokens": 500,
    }
)

assert budget.total_tokens == 500
assert budget.input_tokens == 400
assert budget.output_tokens == 100
assert budget.completed_calls == 1
assert budget.can_continue()

budget.record_usage(
    {
        "input_tokens": 450,
        "output_tokens": 100,
        "total_tokens": 550,
    }
)

assert budget.total_tokens == 1050
assert budget.completed_calls == 2
assert not budget.can_continue()

print(
    "PASS - token budget accounting"
)


budget.record_failure()
budget.record_skip()

summary = budget.summary()

assert summary["failed_calls"] == 1
assert summary["skipped_calls"] == 1
assert summary["limit_reached"] is True

print(
    "PASS - failure/skip accounting"
)

print(
    "PASS - hard token ceiling detected"
)

print()
print(
    "All AI budget tests passed."
)