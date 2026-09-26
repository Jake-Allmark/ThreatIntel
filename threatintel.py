import argparse
import sys
from datetime import datetime
from pathlib import Path

from collectors.multi import collect_all_feeds

from config import (
    AI_MAX_EVENTS_PER_RUN,
    AI_MAX_TOTAL_TOKENS_PER_RUN,
    AI_MIN_PRIORITY,
    AIRunBudget,
    COLLECTION_HOURS,
    select_events_for_ai,
)

from processing.correlate import correlate_records
from processing.customer_assets import apply_customer_asset_correlation
from processing.hunt_selector import select_hunts
from processing.kev import build_kev_index, download_kev
from processing.process import enrich_event_with_ai, process_items
from processing.relevance import apply_relevance_to_events

from ai.hunt_generator import generate_hunt_pack

from reporting.json_report import build_report, serialize_report, write_report
from reporting.pdf import build_pdf
from reporting.terminal import (
    console,
    show_ai_details,
    show_banner,
    show_event_table,
    show_run_summary,
    show_source_status,
)


PRIORITY_ORDER = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "INFORMATIONAL": 1,
}


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="ThreatIntel - defensive cyber threat intelligence collector"
    )

    output_group = parser.add_mutually_exclusive_group()

    output_group.add_argument(
        "--json",
        action="store_true",
        help="Output the complete report as JSON to standard output.",
    )

    output_group.add_argument(
        "--json-file",
        metavar="PATH",
        help="Write the complete report directly to a UTF-8 JSON file.",
    )

    parser.add_argument(
        "--no-ai",
        action="store_true",
        help="Disable OpenAI enrichment and AI threat-hunt generation.",
    )

    return parser.parse_args()


def priority_rank(event):
    priority = event.get("priority", {}) or {}
    level = priority.get("level", "INFORMATIONAL")
    score = priority.get("score", 0)

    return (
        PRIORITY_ORDER.get(level, 1),
        score,
    )


def load_kev(quiet=False):
    if not quiet:
        console.print(
            "\nLoading CISA Known Exploited Vulnerabilities..."
        )

    try:
        records = download_kev()
        index = build_kev_index(records)

        if not quiet:
            console.print(
                "[green]OK[/green] "
                f"Loaded [bold]{len(index)}[/bold] KEV records."
            )

        return index

    except Exception as error:
        if not quiet:
            console.print(
                "[yellow]WARNING[/yellow] "
                f"CISA KEV could not be loaded: {error}"
            )

        return {}


def empty_ai_usage():
    return {
        "input_tokens": 0,
        "output_tokens": 0,
        "total_tokens": 0,
        "completed_calls": 0,
        "failed_calls": 0,
        "skipped_calls": 0,
        "token_limit": AI_MAX_TOTAL_TOKENS_PER_RUN,
        "limit_reached": False,
    }


def run_ai_enrichment(events, quiet=False):
    selected = select_events_for_ai(events)

    budget = AIRunBudget(
        max_total_tokens=AI_MAX_TOTAL_TOKENS_PER_RUN
    )

    if not quiet:
        console.print(
            "\n[bold cyan]AI Enrichment[/bold cyan]"
        )

        console.print(
            f"Minimum priority: "
            f"[bold]{AI_MIN_PRIORITY}[/bold]"
        )

        if AI_MAX_EVENTS_PER_RUN <= 0:
            event_limit_text = "unlimited"
        else:
            event_limit_text = str(
                AI_MAX_EVENTS_PER_RUN
            )

        console.print(
            f"Maximum events: "
            f"[bold]{event_limit_text}[/bold]"
        )

        if AI_MAX_TOTAL_TOKENS_PER_RUN <= 0:
            token_limit_text = "unlimited"
        else:
            token_limit_text = (
                f"{AI_MAX_TOTAL_TOKENS_PER_RUN:,}"
            )

        console.print(
            f"Token budget: "
            f"[bold]{token_limit_text}[/bold]"
        )

        console.print(
            f"Selected: "
            f"[bold]{len(selected)}[/bold]\n"
        )

    for number, event in enumerate(
        selected,
        start=1,
    ):
        title = event.get(
            "title",
            "Untitled event",
        )

        if not budget.can_continue():
            event["ai_status"] = (
                "skipped_budget"
            )

            event["ai_error"] = (
                "AI run token budget reached"
            )

            budget.record_skip()

            if not quiet:
                console.print(
                    f"[dim]"
                    f"[{number}/{len(selected)}]"
                    f"[/dim] "
                    f"{title}"
                )

                console.print(
                    "    "
                    "[yellow]"
                    "SKIPPED - token budget reached"
                    "[/yellow]"
                )

            continue

        if not quiet:
            console.print(
                f"[dim]"
                f"[{number}/{len(selected)}]"
                f"[/dim] "
                f"{title}"
            )

        try:
            enrich_event_with_ai(
                event
            )

        except Exception as error:
            event["ai_status"] = "failed"
            event["ai_error"] = str(
                error
            )

        if (
            event.get(
                "ai_status"
            )
            == "success"
        ):
            usage = (
                event.get(
                    "ai_usage"
                )
                or {}
            )

            budget.record_usage(
                usage
            )

            if not quiet:
                grounding = (
                    event.get(
                        "grounding"
                    )
                    or {}
                )

                console.print(
                    "    "
                    "[green]"
                    "OK - AI complete"
                    "[/green] "
                    f"[dim]"
                    f"{usage.get('total_tokens', '?')} "
                    f"tokens | "
                    f"grounding="
                    f"{grounding.get('passed')}"
                    f"[/dim]"
                )

        else:
            budget.record_failure()

            if not quiet:
                console.print(
                    "    "
                    "[yellow]"
                    "AI failed"
                    "[/yellow] "
                    f"{event.get('ai_error')}"
                )

    summary = budget.summary()

    if not quiet:
        console.print(
            "\n[bold cyan]"
            "AI Run Usage"
            "[/bold cyan]"
        )

        console.print(
            f"Successful calls: "
            f"[bold]"
            f"{summary['completed_calls']}"
            f"[/bold]"
        )

        console.print(
            f"Failed calls: "
            f"[bold]"
            f"{summary['failed_calls']}"
            f"[/bold]"
        )

        console.print(
            f"Budget-skipped calls: "
            f"[bold]"
            f"{summary['skipped_calls']}"
            f"[/bold]"
        )

        console.print(
            f"Input tokens: "
            f"[bold]"
            f"{summary['input_tokens']:,}"
            f"[/bold]"
        )

        console.print(
            f"Output tokens: "
            f"[bold]"
            f"{summary['output_tokens']:,}"
            f"[/bold]"
        )

        console.print(
            f"Total tokens: "
            f"[bold]"
            f"{summary['total_tokens']:,}"
            f"[/bold]"
        )

        if summary["limit_reached"]:
            console.print(
                "[yellow]"
                "AI token budget reached. "
                "Remaining eligible events were "
                "left deterministically enriched."
                "[/yellow]"
            )

    return selected, summary


def run_threat_hunts(
    events,
    *,
    use_ai=True,
    quiet=False,
):
    if not use_ai:
        return []

    try:
        selections = select_hunts(
            events
        )

    except Exception as error:
        if not quiet:
            console.print(
                "\n[yellow]"
                "Threat-hunt selection failed: "
                f"{error}"
                "[/yellow]"
            )

        return []

    selections = selections[:3]

    if not quiet:
        console.print(
            "\n[bold cyan]"
            "AI Threat Hunt Packs"
            "[/bold cyan]"
        )

        console.print(
            "Selected hunt candidates: "
            f"[bold]{len(selections)}[/bold]"
        )

    hunt_packs = []

    for number, selection_wrapper in enumerate(
        selections,
        start=1,
    ):
        event = selection_wrapper.get(
            "event"
        )

        hunt_selection = (
            selection_wrapper.get(
                "hunt_selection"
            )
        )

        if not isinstance(
            event,
            dict,
        ):
            if not quiet:
                console.print(
                    f"[{number}/{len(selections)}] "
                    "[yellow]"
                    "Skipped invalid hunt event."
                    "[/yellow]"
                )

            continue

        if not isinstance(
            hunt_selection,
            dict,
        ):
            if not quiet:
                console.print(
                    f"[{number}/{len(selections)}] "
                    "[yellow]"
                    "Skipped invalid hunt selection."
                    "[/yellow]"
                )

            continue

        title = event.get(
            "title",
            "Untitled event",
        )

        if not quiet:
            console.print(
                f"[dim]"
                f"[{number}/{len(selections)}]"
                f"[/dim] "
                f"{title}"
            )

        try:
            hunt_pack = generate_hunt_pack(
                event,
                hunt_selection,
            )

            result = {
                "event_title": title,
                "selection": {
                    "score": (
                        hunt_selection.get(
                            "score"
                        )
                    ),
                    "behaviours": (
                        hunt_selection.get(
                            "behaviours",
                            [],
                        )
                    ),
                    "telemetry": (
                        hunt_selection.get(
                            "telemetry",
                            [],
                        )
                    ),
                    "reasons": (
                        hunt_selection.get(
                            "reasons",
                            [],
                        )
                    ),
                    "active_exploitation": (
                        hunt_selection.get(
                            "active_exploitation",
                            False,
                        )
                    ),
                    "managed_estate_relevant": (
                        hunt_selection.get(
                            "managed_estate_relevant",
                            False,
                        )
                    ),
                },
                "hunt_pack": hunt_pack,
            }

            hunt_packs.append(
                result
            )

            if not quiet:
                validation = (
                    hunt_pack.get(
                        "validation",
                        {},
                    )
                    or {}
                )

                if validation.get(
                    "passed"
                ):
                    console.print(
                        "    "
                        "[green]"
                        "OK - hunt pack generated "
                        "and validated"
                        "[/green]"
                    )

                else:
                    console.print(
                        "    "
                        "[yellow]"
                        "Generated, but local "
                        "validation found problems"
                        "[/yellow]"
                    )

                    for problem in (
                        validation.get(
                            "problems",
                            [],
                        )
                    ):
                        console.print(
                            f"      - {problem}"
                        )

        except Exception as error:
            if not quiet:
                console.print(
                    "    "
                    "[yellow]"
                    "Hunt generation failed: "
                    f"{error}"
                    "[/yellow]"
                )

    return hunt_packs


def attach_hunts_to_report(
    report,
    hunt_packs,
):
    report["threat_hunts"] = (
        hunt_packs
    )

    report["threat_hunt_summary"] = {
        "generated": len(
            hunt_packs
        ),
        "maximum_per_run": 3,
        "review_required": True,
        "deployment_status": (
            "REVIEW BEFORE DEPLOYMENT"
        ),
    }


def collect_pipeline(
    *,
    use_ai=True,
    quiet=False,
):
    if not quiet:
        show_banner()

        console.print(
            f"\nCollecting intelligence from the "
            f"last "
            f"[bold]{COLLECTION_HOURS}[/bold] "
            f"hours...\n"
        )

    if quiet:
        status_callback = None
    else:
        status_callback = (
            show_source_status
        )

    collection = collect_all_feeds(
        hours=COLLECTION_HOURS,
        status_callback=status_callback,
    )

    items = collection.get(
        "items",
        [],
    )

    failures = collection.get(
        "failures",
        [],
    )

    if not quiet:
        console.print(
            f"\nCollected "
            f"[bold]{len(items)}[/bold] "
            f"reports."
        )

    if not items:
        ai_usage = empty_ai_usage()

        report = build_report(
            [],
            collection_hours=(
                COLLECTION_HOURS
            ),
            report_count=0,
            failures=failures,
            ai_usage=ai_usage,
        )

        attach_hunts_to_report(
            report,
            [],
        )

        return {
            "report": report,
            "events": [],
            "items": [],
            "failures": failures,
            "selected": [],
            "ai_usage": ai_usage,
            "hunt_packs": [],
        }

    kev_index = load_kev(
        quiet=quiet
    )

    if not quiet:
        console.print(
            "\nProcessing article evidence, "
            "CVEs, IOCs and NVD enrichment..."
        )

    processed = process_items(
        items,
        kev_index=kev_index,
    )

    if not quiet:
        console.print(
            "[green]OK[/green] "
            f"Processed "
            f"[bold]{len(processed)}[/bold] "
            f"reports."
        )

        console.print(
            "\nCorrelating related reporting..."
        )

    events = correlate_records(
        processed
    )

    #
    # Relevance is applied after correlation so the
    # classifier sees the complete event evidence.
    #
    apply_relevance_to_events(
        events
    )

    #
    # Match against the combined managed-customer
    # technology catalogue.
    #
    # This indicates estate relevance only.
    # It does not establish customer vulnerability
    # or compromise.
    #
    apply_customer_asset_correlation(
        events
    )

    events.sort(
        key=priority_rank,
        reverse=True,
    )

    if not quiet:
        console.print(
            "[green]OK[/green] "
            f"Produced "
            f"[bold]{len(events)}[/bold] "
            f"correlated threat events."
        )

    if use_ai:
        selected, ai_usage = (
            run_ai_enrichment(
                events,
                quiet=quiet,
            )
        )

    else:
        selected = []
        ai_usage = empty_ai_usage()

        for event in events:
            event["ai_status"] = (
                "disabled"
            )

    #
    # Threat hunts are generated after relevance,
    # priority and managed-estate correlation.
    #
    # They are always REVIEW BEFORE DEPLOYMENT.
    #
    hunt_packs = run_threat_hunts(
        events,
        use_ai=use_ai,
        quiet=quiet,
    )

    report = build_report(
        events,
        collection_hours=(
            COLLECTION_HOURS
        ),
        report_count=len(items),
        failures=failures,
        ai_usage=ai_usage,
    )

    attach_hunts_to_report(
        report,
        hunt_packs,
    )

    return {
        "report": report,
        "events": events,
        "items": items,
        "failures": failures,
        "selected": selected,
        "ai_usage": ai_usage,
        "hunt_packs": hunt_packs,
    }


def show_terminal_result(
    result,
):
    events = result["events"]
    items = result["items"]
    failures = result["failures"]
    selected = result["selected"]

    hunt_packs = result.get(
        "hunt_packs",
        [],
    )

    if not items:
        console.print(
            "[yellow]"
            "No reports were collected."
            "[/yellow]"
        )

        show_run_summary(
            report_count=0,
            event_count=0,
            ai_count=0,
            failed_sources=failures,
        )

        return

    show_event_table(
        events
    )

    show_ai_details(
        events
    )

    if hunt_packs:
        console.print(
            "\n[bold cyan]"
            "Threat Hunt Packs"
            "[/bold cyan]"
        )

        for number, item in enumerate(
            hunt_packs,
            start=1,
        ):
            pack = (
                item.get(
                    "hunt_pack"
                )
                or {}
            )

            validation = (
                pack.get(
                    "validation"
                )
                or {}
            )

            if validation.get(
                "passed"
            ):
                status = (
                    "[green]VALIDATED[/green]"
                )
            else:
                status = (
                    "[yellow]"
                    "REVIEW REQUIRED"
                    "[/yellow]"
                )

            console.print(
                f"{number}. "
                f"{pack.get('title', item.get('event_title'))} "
                f"- {status}"
            )

        console.print(
            "\n[dim]"
            "All hunt queries are "
            "REVIEW BEFORE DEPLOYMENT."
            "[/dim]"
        )

    show_run_summary(
        report_count=len(items),
        event_count=len(events),
        ai_count=sum(
            1
            for event in selected
            if event.get(
                "ai_status"
            )
            == "success"
        ),
        failed_sources=failures,
    )

    if failures:
        console.print(
            "\n[yellow]"
            "One or more collection sources failed, "
            "but ThreatIntel completed using the "
            "remaining evidence."
            "[/yellow]"
        )

    console.print(
        "\n[bold green]"
        "OK - ThreatIntel run complete."
        "[/bold green]"
    )


def prepare_json_path(
    value,
):
    path = Path(
        value
    ).expanduser()

    if path.suffix.lower() != ".json":
        raise ValueError(
            "--json-file must point to "
            "a .json file"
        )

    parent = path.parent

    if str(parent) not in (
        "",
        ".",
    ):
        parent.mkdir(
            parents=True,
            exist_ok=True,
        )

    return path


def write_json_file(
    report,
    file_name,
):
    path = prepare_json_path(
        file_name
    )

    write_report(
        report,
        path,
        pretty=True,
    )

    return path.resolve()


def write_json_stdout(
    report,
):
    content = serialize_report(
        report,
        pretty=True,
    )

    try:
        sys.stdout.reconfigure(
            encoding="utf-8",
            errors="strict",
        )

    except (
        AttributeError,
        ValueError,
    ):
        pass

    sys.stdout.write(
        content
    )

    sys.stdout.write(
        "\n"
    )


def build_default_output_paths():
    reports_dir = Path(
        "reports"
    )

    reports_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    timestamp = datetime.now().strftime(
        "%Y-%m-%d_%H-%M-%S"
    )

    base_name = (
        f"Threat-Intelligence-{timestamp}"
    )

    json_path = (
        reports_dir
        / f"{base_name}.json"
    )

    pdf_path = (
        reports_dir
        / f"{base_name}.pdf"
    )

    return (
        json_path,
        pdf_path,
    )


def write_default_reports(
    report,
):
    (
        json_path,
        pdf_path,
    ) = build_default_output_paths()

    #
    # JSON is the canonical preserved output.
    #
    write_report(
        report,
        json_path,
        pretty=True,
    )

    json_result = (
        json_path.resolve()
    )

    pdf_result = None
    pdf_error = None

    #
    # A PDF rendering failure must not destroy
    # the successful ThreatIntel JSON report.
    #
    try:
        build_pdf(
            report,
            pdf_path,
        )

        pdf_result = (
            pdf_path.resolve()
        )

    except Exception as error:
        pdf_error = str(
            error
        )

        try:
            if pdf_path.exists():
                pdf_path.unlink()

        except OSError:
            pass

    return {
        "json_path": json_result,
        "pdf_path": pdf_result,
        "pdf_error": pdf_error,
    }


def show_saved_reports(
    output,
):
    console.print(
        "\n[bold cyan]"
        "Saved Reports"
        "[/bold cyan]"
    )

    console.print(
        "[green]JSON[/green] "
        f"{output['json_path']}"
    )

    if output.get(
        "pdf_path"
    ):
        console.print(
            "[green]PDF[/green]  "
            f"{output['pdf_path']}"
        )

    else:
        console.print(
            "[yellow]PDF[/yellow]  "
            "Could not be generated."
        )

        console.print(
            "[yellow]"
            f"{output.get('pdf_error')}"
            "[/yellow]"
        )


def main():
    args = parse_arguments()

    json_mode = (
        args.json
        or bool(
            args.json_file
        )
    )

    result = collect_pipeline(
        use_ai=not args.no_ai,
        quiet=json_mode,
    )

    #
    # Explicit JSON modes keep their existing
    # behaviour and do not automatically create
    # a PDF.
    #
    if args.json_file:
        try:
            path = write_json_file(
                result["report"],
                args.json_file,
            )

        except (
            OSError,
            ValueError,
        ) as error:
            print(
                f"ERROR: {error}",
                file=sys.stderr,
            )

            raise SystemExit(
                1
            )

        print(
            "ThreatIntel JSON report written to:",
            file=sys.stderr,
        )

        print(
            path,
            file=sys.stderr,
        )

        return

    if args.json:
        write_json_stdout(
            result["report"]
        )

        return

    #
    # Normal interactive runs automatically create
    # timestamped JSON and PDF reports.
    #
    show_terminal_result(
        result
    )

    try:
        output = write_default_reports(
            result["report"]
        )

    except OSError as error:
        console.print(
            "\n[bold red]"
            "ERROR - ThreatIntel completed, "
            "but the JSON report could not be saved."
            "[/bold red]"
        )

        console.print(
            f"[red]{error}[/red]"
        )

        raise SystemExit(
            1
        )

    show_saved_reports(
        output
    )

    if output.get(
        "pdf_error"
    ):
        console.print(
            "\n[yellow]"
            "ThreatIntel completed successfully, "
            "but PDF generation failed. "
            "The JSON report was preserved."
            "[/yellow]"
        )


if __name__ == "__main__":
    main()