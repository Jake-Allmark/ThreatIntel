from collectors.feeds import collect_feed
from collectors.sources import get_enabled_feeds


def collect_all_feeds(hours=24, status_callback=None):
    """
    Collect reports from every enabled feed.

    One broken source must never stop collection from
    the remaining sources.

    Returns:
        {
            "items": [...],
            "sources": [...],
            "failures": [...]
        }
    """

    all_items = []
    source_results = []
    failures = []

    feeds = get_enabled_feeds()

    for source in feeds:
        name = source["name"]
        url = source["url"]

        try:
            items = collect_feed(
                name,
                url,
                hours=hours,
            )

            all_items.extend(items)

            result = {
                "name": name,
                "category": source.get(
                    "category",
                    "unknown",
                ),
                "status": "success",
                "count": len(items),
                "error": None,
            }

            source_results.append(result)

            if status_callback:
                status_callback(result)

        except Exception as error:
            result = {
                "name": name,
                "category": source.get(
                    "category",
                    "unknown",
                ),
                "status": "failed",
                "count": 0,
                "error": str(error),
            }

            source_results.append(result)
            failures.append(result)

            if status_callback:
                status_callback(result)

    # Newest reports first across all publishers.

    all_items.sort(
        key=lambda item: item["published_at"],
        reverse=True,
    )

    return {
        "items": all_items,
        "sources": source_results,
        "failures": failures,
    }