from collectors.article import fetch_article
from collectors.feeds import collect_feed
from collectors.sources import FEEDS
from processing.extract import extract_intelligence

from rich.console import Console
from rich.panel import Panel


console = Console()


for source in FEEDS:
    console.print(
        f"\n[cyan]Testing {source['name']}...[/cyan]"
    )

    try:
        items = collect_feed(
            source["name"],
            source["url"],
        )

        console.print(
            f"[green]✓[/green] "
            f"{len(items)} items found in last 24 hours"
        )

        for item in items:
            console.print(
                Panel(
                    f"[bold]{item['title']}[/bold]\n\n"
                    f"{item['published_at']}\n"
                    f"{item['url']}",
                    border_style="cyan",
                )
            )

        # Analyse the first article from this source.
        if items:
            first = items[0]

            console.print(
                f"\n[yellow]Analysing:[/yellow] "
                f"{first['title']}"
            )

            try:
                article_text = fetch_article(
                    first["url"]
                )

                console.print(
                    f"[green]✓[/green] Extracted "
                    f"{len(article_text):,} characters"
                )

                intelligence = extract_intelligence(
                    article_text
                )

                console.print(
                    Panel(
                        f"[bold]CVEs[/bold]\n"
                        f"{intelligence['cves']}\n\n"
                        f"[bold]IPv4[/bold]\n"
                        f"{intelligence['ipv4']}\n\n"
                        f"[bold]Domains[/bold]\n"
                        f"{intelligence['domains']}\n\n"
                        f"[bold]URLs[/bold]\n"
                        f"{intelligence['urls']}\n\n"
                        f"[bold]MD5[/bold]\n"
                        f"{intelligence['hashes']['md5']}\n\n"
                        f"[bold]SHA1[/bold]\n"
                        f"{intelligence['hashes']['sha1']}\n\n"
                        f"[bold]SHA256[/bold]\n"
                        f"{intelligence['hashes']['sha256']}",
                        title="Extracted Intelligence",
                        border_style="magenta",
                    )
                )

            except Exception as error:
                console.print(
                    "[red]✗ Article analysis failed:[/red] "
                    f"{error}"
                )

    except Exception as error:
        console.print(
            f"[red]✗ FAILED:[/red] {error}"
        )