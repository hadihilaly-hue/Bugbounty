"""Command-line entrypoint. Phase 0 ships scope/config inspection commands;
finder/validator/orchestrator/dashboard commands are added in later phases.
"""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from bugbounty import __version__
from bugbounty.config import load_config
from bugbounty.scope import load_allowlist

app = typer.Typer(help="Validator-first AI bug-bounty harness (authorized targets only).")
console = Console()

DEFAULT_ALLOWLIST = "targets.yaml"


@app.command()
def version() -> None:
    """Print the harness version."""
    console.print(f"bugbounty {__version__}")


@app.command()
def config() -> None:
    """Show the effective runtime configuration and guardrail state."""
    cfg = load_config()
    table = Table(title="Runtime configuration")
    table.add_column("setting")
    table.add_column("value")
    table.add_row("dry_run (global)", str(cfg.dry_run))
    table.add_row("kill_switch", str(cfg.kill_switch))
    table.add_row("concurrency", str(cfg.concurrency))
    table.add_row("requests_per_second", str(cfg.requests_per_second))
    table.add_row("budget.max_tokens", str(cfg.budget.max_tokens))
    table.add_row("budget.max_requests", str(cfg.budget.max_requests))
    table.add_row("budget.max_wall_clock_seconds", str(cfg.budget.max_wall_clock_seconds))
    table.add_row("budget.max_usd", str(cfg.budget.max_usd))
    console.print(table)


@app.command()
def targets(allowlist: str = DEFAULT_ALLOWLIST) -> None:
    """List targets in the allowlist."""
    al = load_allowlist(allowlist)
    table = Table(title=f"Allowlist ({allowlist})")
    table.add_column("name")
    table.add_column("platform")
    table.add_column("in_scope")
    table.add_column("dry_run")
    table.add_column("ai_policy")
    for t in al.targets:
        table.add_row(
            t.name, t.platform.value, str(len(t.in_scope)), str(t.dry_run), t.ai_policy.value
        )
    console.print(table)


@app.command()
def scope(
    name: str,
    host: str,
    allowlist: str = DEFAULT_ALLOWLIST,
) -> None:
    """Check whether HOST is in scope for the named target, and why."""
    al = load_allowlist(allowlist)
    decision = al.decide(name, host)
    colour = "green" if decision.allowed else "red"
    verdict = "ALLOWED" if decision.allowed else "BLOCKED"
    console.print(f"[{colour}]{verdict}[/]: {decision.host} — {decision.reason}")
    raise typer.Exit(code=0 if decision.allowed else 1)


@app.command()
def validate(
    candidates_file: str,
    allowlist: str = DEFAULT_ALLOWLIST,
) -> None:
    """Run the adversarial validator over a YAML file of candidate findings."""
    import yaml

    from bugbounty.validator import Candidate, Validator

    cfg = load_config()
    al = load_allowlist(allowlist)
    validator = Validator(cfg)
    data = yaml.safe_load(Path(candidates_file).read_text()) or {}
    raw = data.get("candidates") or []
    table = Table(title=f"Validation results ({candidates_file})")
    for col in ("id", "class", "status", "queue", "reason"):
        table.add_column(col)
    for item in raw:
        cand = Candidate.model_validate(item)
        target = al.target_by_name(cand.target_name)
        if target is None:
            table.add_row(cand.id, cand.vuln_class.value, "UNCONFIRMED", "no", "unknown target")
            continue
        decision = al.decide(cand.target_name, cand.host)
        if not decision.allowed:
            table.add_row(
                cand.id,
                cand.vuln_class.value,
                "UNCONFIRMED",
                "no",
                f"out of scope: {decision.reason}",
            )
            continue
        res = validator.validate(cand, target)
        colour = (
            "green"
            if res.in_review_queue
            else ("red" if res.status.value == "rejected" else "yellow")
        )
        table.add_row(
            cand.id,
            cand.vuln_class.value,
            f"[{colour}]{res.status.value.upper()}[/]",
            "yes" if res.in_review_queue else "no",
            res.reason,
        )
    console.print(table)


@app.command(name="bench-juiceshop")
def bench_juiceshop(
    base_url: str = "http://localhost:3000",
    target_name: str = "OWASP Juice Shop (local sandbox)",
    allowlist: str = DEFAULT_ALLOWLIST,
) -> None:
    """Measure validator precision/recall against the local Juice Shop sandbox."""
    from urllib.parse import urlparse

    cfg = load_config()
    al = load_allowlist(allowlist)
    target = al.target_by_name(target_name)
    if target is None:
        console.print(f"[red]no target named {target_name!r} in {allowlist}[/]")
        raise typer.Exit(2)
    host = urlparse(base_url).hostname or base_url
    decision = al.decide(target_name, host)
    if not decision.allowed:
        console.print(f"[red]refusing: {host} is out of scope — {decision.reason}[/]")
        raise typer.Exit(2)
    if not cfg.active_payloads_allowed(target.dry_run):
        console.print(
            "[yellow]active payloads are disabled by the dry-run gate.[/]\n"
            "The benchmark proves bugs on a sandbox you own; re-run with the gate "
            "cleared:\n    DRY_RUN=false bugbounty bench-juiceshop"
        )
        raise typer.Exit(3)

    from bugbounty.validator.benchmark import run_benchmark

    rows, m = run_benchmark(target, cfg, base_url)
    table = Table(title="Juice Shop validator benchmark")
    for col in ("candidate", "class", "expected", "status", "correct"):
        table.add_column(col)
    for cand, expect, res in rows:
        confirmed = res.in_review_queue
        correct = confirmed == expect
        table.add_row(
            cand.id,
            cand.vuln_class.value,
            "VULN" if expect else "SAFE",
            res.status.value.upper(),
            "[green]ok[/]" if correct else "[red]MISS[/]",
        )
    console.print(table)
    console.print(
        f"precision={m.precision:.2f}  recall={m.recall:.2f}  "
        f"fp_rate={m.fp_rate:.2f}  (tp={m.tp} fp={m.fp} tn={m.tn} fn={m.fn})"
    )


def _default_allowlist_exists() -> bool:
    return Path(DEFAULT_ALLOWLIST).exists()


if __name__ == "__main__":
    app()
