from config import select_events_for_ai


def make_event(title, priority, score):
    return {
        "title": title,
        "priority": {
            "level": priority,
            "score": score,
        },
    }


events = [
    make_event(
        "Informational Event",
        "INFORMATIONAL",
        5,
    ),
    make_event(
        "High Event",
        "HIGH",
        45,
    ),
    make_event(
        "Critical Event A",
        "CRITICAL",
        80,
    ),
    make_event(
        "Medium Event",
        "MEDIUM",
        25,
    ),
    make_event(
        "Critical Event B",
        "CRITICAL",
        95,
    ),
    make_event(
        "High Event B",
        "HIGH",
        60,
    ),
]


selected = select_events_for_ai(
    events
)


print(
    "SELECTED:",
    len(selected),
)

for event in selected:
    print(
        event["priority"]["level"],
        event["priority"]["score"],
        "-",
        event["title"],
    )


assert len(selected) == 3

assert selected[0]["title"] == (
    "Critical Event B"
)

assert selected[1]["title"] == (
    "Critical Event A"
)

assert selected[2]["title"] == (
    "High Event B"
)

print(
    "\nPASS: AI cost control is working."
)