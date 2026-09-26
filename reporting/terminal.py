from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text


console = Console()


PRIORITY_STYLES = {
    "CRITICAL": "bold red",
    "HIGH": "bold yellow",
    "MEDIUM": "yellow",
    "INFORMATIONAL": "cyan",
}


def priority_style(level):
    return PRIORITY_STYLES.get(
        level,
        "white",
    )


def show_banner():
    console.print(
        Panel.fit(
            "[bold cyan]ThreatIntel[/bold cyan]\n"
            "[dim]Defensive Cyber Threat Intelligence[/dim]",
            border_style="cyan",
        )
    )


def show_source_status(result):
    if result["status"] == "success":
        console.print(
            f"[green]✓[/green] "
            f"{result['name']} "
            f"[dim]({result['count']} reports)[/dim]"
        )

    else:
        console.print(
            f"[red]✗[/red] "
            f"{result['name']} "
            f"[red]{result['error']}[/red]"
        )


def event_source_text(event):
    sources = event.get(
        "sources",
        [],
    )

    if not sources:
        return event.get(
            "source",
            "Unknown",
        )

    names = sorted(
        {
            source.get(
                "source",
                "Unknown",
            )
            for source in sources
        }
    )

    return ", ".join(names)


def show_event_table(events):
    """
    Display events vertically so titles and sources
    remain readable in narrow PowerShell windows.
    """

    console.print(
        "\n[bold cyan]"
        "Threat Intelligence — Last 24 Hours"
        "[/bold cyan]"
    )

    console.print(
        "[dim]"
        "Ordered by operational priority"
        "[/dim]\n"
    )

    for number, event in enumerate(
        events,
        start=1,
    ):
        if "processing_error" in event:
            console.print(
                f"[bold red]"
                f"{number:02d}  ERROR"
                f"[/bold red]"
            )

            console.print(
                Text(
                    event.get(
                        "title",
                        "Untitled event",
                    ),
                    style="bold",
                )
            )

            console.print(
                "[dim]"
                f"Source: "
                f"{event.get('source', 'Unknown')}"
                "[/dim]\n"
            )

            continue

        priority = event.get(
            "priority",
            {},
        )

        level = priority.get(
            "level",
            "INFORMATIONAL",
        )

        score = priority.get(
            "score",
            0,
        )

        style = priority_style(
            level
        )

        ai_status = event.get(
            "ai_status",
            "not_run",
        )

        if ai_status == "success":
            ai_text = (
                "[green]AI ✓[/green]"
            )

        elif ai_status == "failed":
            ai_text = (
                "[red]AI ✗[/red]"
            )

        elif ai_status == "skipped":
            ai_text = (
                "[yellow]SKIP[/yellow]"
            )

        else:
            ai_text = (
                "[dim]AI —[/dim]"
            )

        console.print(
            f"[bold]{number:02d}[/bold]  "
            f"[{style}]"
            f"{level}"
            f"[/{style}]  "
            f"[bold]{score}[/bold]  "
            f"{ai_text}"
        )

        console.print(
            Text(
                event.get(
                    "title",
                    "Untitled event",
                ),
                style="bold",
            )
        )

        sources = event_source_text(
            event
        )

        source_label = (
            "Sources"
            if ", " in sources
            else "Source"
        )

        console.print(
            f"[dim]"
            f"{source_label}: "
            f"{sources}"
            f"[/dim]"
        )

        cves = event.get(
            "cves",
            [],
        )

        kev = event.get(
            "kev",
            [],
        )

        highest_cvss = priority.get(
            "highest_cvss"
        )

        details = []

        if cves:
            details.append(
                f"CVEs: {len(cves)}"
            )

        if kev:
            details.append(
                f"KEV: {len(kev)}"
            )

        if highest_cvss is not None:
            details.append(
                f"Highest CVSS: "
                f"{highest_cvss:g}"
            )

        if details:
            console.print(
                "[dim]"
                + "  •  ".join(
                    details
                )
                + "[/dim]"
            )

        reasons = priority.get(
            "reasons",
            [],
        )

        if reasons:
            console.print(
                "[dim]"
                "Why: "
                + reasons[0]
                + "[/dim]"
            )

        console.print()


def show_ai_details(events):
    successful = [
        event
        for event in events
        if event.get(
            "ai_status"
        ) == "success"
    ]

    if not successful:
        return

    console.print(
        "\n[bold cyan]"
        "AI-Enriched Priority Intelligence"
        "[/bold cyan]\n"
    )

    for event in successful:
        analysis = event.get(
            "ai_analysis",
            {},
        )

        priority = event.get(
            "priority",
            {},
        )

        level = priority.get(
            "level",
            "INFORMATIONAL",
        )

        exploitation = analysis.get(
            "exploitation",
            {},
        ).get(
            "status",
            "unknown",
        )

        confidence = analysis.get(
            "confidence",
            "unknown",
        )

        grounding = (
            event.get(
                "grounding"
            )
            or {}
        )

        usage = (
            event.get(
                "ai_usage"
            )
            or {}
        )

        sources = event_source_text(
            event
        )

        summary = analysis.get(
            "executive_summary",
            "No summary available.",
        )

        header = Table.grid(
            padding=(0, 2),
        )

        header.add_column(
            style="bold",
        )

        header.add_column()

        header.add_row(
            "Priority",
            Text(
                level,
                style=priority_style(
                    level
                ),
            ),
        )

        header.add_row(
            "Score",
            str(
                priority.get(
                    "score",
                    0,
                )
            ),
        )

        header.add_row(
            "Exploitation",
            exploitation,
        )

        header.add_row(
            "Confidence",
            confidence,
        )

        header.add_row(
            "Sources",
            sources,
        )

        header.add_row(
            "Grounding",
            (
                "PASS"
                if grounding.get(
                    "passed"
                )
                else "REVIEW"
            ),
        )

        header.add_row(
            "AI tokens",
            str(
                usage.get(
                    "total_tokens",
                    "unknown",
                )
            ),
        )

        body = Table.grid(
            expand=True,
        )

        body.add_row(
            header
        )

        body.add_row(
            ""
        )

        body.add_row(
            Text(
                summary
            )
        )

        console.print(
            Panel(
                body,
                title=analysis.get(
                    "title",
                    event.get(
                        "title",
                        "Threat Event",
                    ),
                ),
                subtitle=(
                    "Grounded threat intelligence"
                ),
                border_style=priority_style(
                    level
                ),
                padding=(1, 2),
            )
        )


def show_run_summary(
    report_count,
    event_count,
    ai_count,
    failed_sources,
):
    summary = Table.grid(
        padding=(0, 2),
    )

    summary.add_row(
        "[bold]Reports collected[/bold]",
        str(report_count),
    )

    summary.add_row(
        "[bold]Correlated events[/bold]",
        str(event_count),
    )

    summary.add_row(
        "[bold]AI enriched[/bold]",
        str(ai_count),
    )

    summary.add_row(
        "[bold]Source failures[/bold]",
        str(
            len(
                failed_sources
            )
        ),
    )

    console.print(
        Panel(
            summary,
            title="Run Summary",
            border_style="cyan",
        )
    )