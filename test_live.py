from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from collectors.multi import collect_all_feeds
from processing.correlate import correlate_records
from processing.kev import (
    build_kev_index,
    download_kev,
)
from processing.process import process_items


console = Console()

PRIORITY_ORDER = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "INFORMATIONAL": 3,
}


def show_source_status(result):
    """
    Display collection status for one source.
    """

    name = result["name"]

    if result["status"] == "success":
        console.print(
            f"[green]✓[/green] "
            f"{name}: "
            f"{result['count']} report(s)"
        )
    else:
        console.print(
            f"[red]✗[/red] "
            f"{name}: FAILED"
        )

        console.print(
            f"  [dim]{result['error']}[/dim]"
        )


def main():
    console.print(
        Panel.fit(
            "[bold]THREAT INTELLIGENCE[/bold]\n"
            "[cyan]Multi-Source 24-Hour Analysis[/cyan]",
            border_style="bright_red",
        )
    )

    # -----------------------------------------
    # Load CISA KEV
    # -----------------------------------------

    console.print(
        "\n[cyan]Loading CISA KEV...[/cyan]"
    )

    kev_records = download_kev()

    kev_index = build_kev_index(
        kev_records
    )

    console.print(
        f"[green]✓[/green] "
        f"{len(kev_index):,} KEV records loaded"
    )

    # -----------------------------------------
    # Collect every enabled source
    # -----------------------------------------

    console.print(
        "\n[cyan]Collecting intelligence "
        "sources...[/cyan]"
    )

    collection = collect_all_feeds(
        hours=24,
        status_callback=show_source_status,
    )

    items = collection["items"]

    console.print(
        f"\n[bold]{len(items)}[/bold] "
        "reports collected from "
        f"[bold]{len(collection['sources'])}[/bold] "
        "configured sources."
    )

    if not items:
        console.print(
            Panel(
                "No reports were collected during "
                "the requested 24-hour window.",
                title="No Intelligence",
            )
        )

        return

    # -----------------------------------------
    # Process and enrich reports
    # -----------------------------------------

    console.print(
        "\n[yellow]Analysing reports...[/yellow]"
    )

    processed = []

    total = len(items)

    for number, item in enumerate(
        items,
        start=1,
    ):
        console.print(
            f"  [{number}/{total}] "
            f"[dim]{item['source']}[/dim] — "
            f"{item['title'][:60]}"
        )

        result = process_items(
            [item],
            kev_index=kev_index,
        )

        processed.extend(
            result
        )

    successful = [
        item
        for item in processed
        if "processing_error" not in item
    ]

    failed_items = [
        item
        for item in processed
        if "processing_error" in item
    ]

    # -----------------------------------------
    # Correlate into threat events
    # -----------------------------------------

    console.print(
        "\n[cyan]Correlating threat "
        "reports...[/cyan]"
    )

    events = correlate_records(
        successful
    )

    console.print(
        f"[green]✓[/green] "
        f"{len(successful)} reports became "
        f"{len(events)} threat events"
    )

    # -----------------------------------------
    # Sort by operational priority
    # -----------------------------------------

    events.sort(
        key=lambda item: (
            PRIORITY_ORDER.get(
                item["priority"]["level"],
                99,
            ),
            -item["priority"]["score"],
        )
    )

    # -----------------------------------------
    # Main intelligence table
    # -----------------------------------------

    table = Table(
        title="24-Hour Threat Intelligence",
        show_lines=True,
    )

    table.add_column(
        "Priority",
        style="bold",
        width=12,
    )

    table.add_column(
        "Score",
        justify="right",
        width=5,
    )

    table.add_column(
        "Threat",
    )

    table.add_column(
        "CVEs",
        width=20,
    )

    table.add_column(
        "Sources",
        justify="center",
        width=7,
    )

    table.add_column(
        "KEV",
        justify="center",
        width=5,
    )

    for item in events:
        priority = item["priority"]

        level = priority["level"]

        if level == "CRITICAL":
            display_level = (
                "[bold red]CRITICAL[/bold red]"
            )

        elif level == "HIGH":
            display_level = (
                "[red]HIGH[/red]"
            )

        elif level == "MEDIUM":
            display_level = (
                "[yellow]MEDIUM[/yellow]"
            )

        else:
            display_level = (
                "[green]INFO[/green]"
            )

        cves = ", ".join(
            item.get(
                "cves",
                [],
            )
        )

        if not cves:
            cves = "-"

        source_count = item.get(
            "correlation",
            {},
        ).get(
            "source_count",
            1,
        )

        kev_status = (
            "YES"
            if item.get("kev")
            else "-"
        )

        table.add_row(
            display_level,
            str(priority["score"]),
            item.get(
                "title",
                "Untitled threat",
            ),
            cves,
            str(source_count),
            kev_status,
        )

    console.print()
    console.print(table)

    # -----------------------------------------
    # Important threat details
    # -----------------------------------------

    for item in events:
        if item["priority"]["level"] not in (
            "CRITICAL",
            "HIGH",
        ):
            continue

        priority = item["priority"]

        reasons = "\n".join(
            f"• {reason}"
            for reason in priority[
                "reasons"
            ]
        )

        source_lines = "\n".join(
            (
                f"• {source.get('source', 'Unknown')}: "
                f"{source.get('url', '')}"
            )
            for source in item.get(
                "sources",
                [],
            )
        )

        if not source_lines:
            source_lines = (
                "• No source provenance available"
            )

        console.print(
            Panel(
                f"[bold]{item['title']}[/bold]\n\n"
                f"[bold]Why prioritised[/bold]\n"
                f"{reasons}\n\n"
                f"[bold]Evidence sources[/bold]\n"
                f"{source_lines}",
                title=(
                    f"{priority['level']} "
                    f"— Score {priority['score']}"
                ),
                border_style="red",
            )
        )

    # -----------------------------------------
    # Final run summary
    # -----------------------------------------

    successful_sources = sum(
        1
        for source in collection["sources"]
        if source["status"] == "success"
    )

    console.print(
        Panel(
            f"Sources configured: "
            f"[bold]{len(collection['sources'])}[/bold]\n"
            f"Sources successful: "
            f"[bold green]{successful_sources}[/bold green]\n"
            f"Source failures: "
            f"[bold red]{len(collection['failures'])}[/bold red]\n"
            f"Reports collected: "
            f"[bold]{len(items)}[/bold]\n"
            f"Reports processed: "
            f"[bold]{len(successful)}[/bold]\n"
            f"Report processing failures: "
            f"[bold]{len(failed_items)}[/bold]\n"
            f"Threat events: "
            f"[bold]{len(events)}[/bold]",
            title="Run Summary",
        )
    )


if __name__ == "__main__":
    main()