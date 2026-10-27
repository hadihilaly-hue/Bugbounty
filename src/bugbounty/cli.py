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


@app.command(name="run-batch")
def run_batch(
    candidates_file: str,
    allowlist: str = DEFAULT_ALLOWLIST,
    db: str = "runs/bugbounty.db",
    batch_id: str | None = None,
    resume: bool = False,
    kill_switch_file: str | None = None,
) -> None:
    """Validate a batch of candidates with persistence, budgets, and kill switch."""
    import yaml

    from bugbounty.orchestrator import CreditWindow, Orchestrator, Store
    from bugbounty.validator import Candidate

    cfg = load_config()
    al = load_allowlist(allowlist)
    data = yaml.safe_load(Path(candidates_file).read_text()) or {}
    cands = [Candidate.model_validate(x) for x in (data.get("candidates") or [])]
    orch = Orchestrator(
        cfg,
        Store(db),
        credit=CreditWindow.from_env(),
        kill_switch_file=kill_switch_file,
    )
    res = orch.run_batch(al, cands, batch_id=batch_id, resume=resume)
    console.print(
        f"batch [bold]{res.batch_id}[/]: "
        f"[green]confirmed={res.confirmed}[/] rejected={res.rejected} "
        f"unconfirmed={res.unconfirmed} out_of_scope={res.out_of_scope}"
    )
    for w in res.warnings:
        console.print(f"[yellow]SPEND WARNING: {w}[/]")
    if res.aborted:
        console.print(f"[red]ABORTED: {res.reason}[/]")
        raise typer.Exit(4)
    console.print(f"persisted to {db}; {res.confirmed} finding(s) in the review queue")


@app.command()
def find(
    target_name: str,
    base_url: str | None = None,
    code_path: str | None = None,
    out: str | None = None,
    use_llm: bool = True,
    allowlist: str = DEFAULT_ALLOWLIST,
) -> None:
    """Propose candidate findings (recon + signal + optional Anthropic reasoning)."""
    from urllib.parse import urlparse

    import yaml

    from bugbounty.finder import AnthropicReasoner, Finder

    cfg = load_config()
    al = load_allowlist(allowlist)
    target = al.target_by_name(target_name)
    if target is None:
        console.print(f"[red]no target named {target_name!r} in {allowlist}[/]")
        raise typer.Exit(2)
    if base_url:
        host = urlparse(base_url).hostname or base_url
        decision = al.decide(target_name, host)
        if not decision.allowed:
            console.print(f"[red]refusing: {host} is out of scope — {decision.reason}[/]")
            raise typer.Exit(2)

    reasoner = AnthropicReasoner() if use_llm else None
    res = Finder(cfg, reasoner=reasoner).find(
        target, base_url=base_url, code_path=code_path, use_llm=use_llm
    )
    table = Table(title=f"Candidates for {target_name}")
    for col in ("id", "class", "source", "title"):
        table.add_column(col)
    for c in res.candidates:
        table.add_row(c.id, c.vuln_class.value, c.source, c.title)
    console.print(table)
    for n in res.notes:
        console.print(f"[dim]note: {n}[/]")
    console.print(
        f"{len(res.candidates)} candidate(s); llm cost ${res.cost_usd:.4f} "
        f"(in={res.input_tokens} out={res.output_tokens})"
    )
    if out:
        Path(out).write_text(
            yaml.safe_dump({"candidates": [c.model_dump(mode="json") for c in res.candidates]})
        )
        console.print(f"wrote {out}")


@app.command()
def dashboard(
    db: str = "runs/bugbounty.db",
    host: str = "127.0.0.1",
    port: int = 8787,
) -> None:
    """Serve the local review dashboard (confirmed findings first)."""
    import uvicorn

    from bugbounty.dashboard import create_app

    console.print(f"serving review dashboard for {db} at http://{host}:{port}")
    uvicorn.run(create_app(db), host=host, port=port)


@app.command()
def report(db: str = "runs/bugbounty.db", out: str | None = None) -> None:
    """Print (or write) the nightly report: findings, benchmark, spend warnings."""
    from bugbounty.jobs.report import build_report
    from bugbounty.orchestrator import Store

    text = build_report(Store(db))
    if out:
        Path(out).write_text(text)
        console.print(f"wrote {out}")
    else:
        console.print(text)


@app.command(name="scan-code")
def scan_code(
    path: str,
    config: list[str] = typer.Option(  # noqa: B008
        None, "--config", help="Semgrep ruleset(s); repeat. Defaults to security packs."
    ),
) -> None:
    """Run Semgrep over your own code at PATH and list the signals."""
    from bugbounty.signal.base import SignalUnavailable
    from bugbounty.signal.semgrep import DEFAULT_RULESETS, run_semgrep

    rulesets = config or list(DEFAULT_RULESETS)
    try:
        sigs = run_semgrep(path, config=rulesets)
    except SignalUnavailable as exc:
        console.print(f"[red]{exc}[/]")
        raise typer.Exit(2) from exc
    table = Table(title=f"Semgrep signals ({path})")
    for col in ("rule", "severity", "location", "message"):
        table.add_column(col)
    for sig in sigs[:200]:
        table.add_row(sig.kind, sig.severity, sig.location, (sig.message or "")[:80])
    console.print(table)
    console.print(f"{len(sigs)} signal(s)")


@app.command(name="fp-benchmark")
def fp_benchmark(db: str | None = None) -> None:
    """Validator false-positive benchmark on vulnerable-vs-patched fixtures."""
    from bugbounty.jobs.fp_benchmark import run_fp_benchmark

    metrics, rows = run_fp_benchmark()
    table = Table(title="FP benchmark (vulnerable vs patched)")
    for col in ("candidate", "expected", "validator"):
        table.add_column(col)
    for cid, vulnerable, status in rows:
        table.add_row(cid, "vulnerable" if vulnerable else "patched", status)
    console.print(table)
    console.print(
        f"precision={metrics.precision:.2f} recall={metrics.recall:.2f} "
        f"fp_rate={metrics.fp_rate:.2f} "
        f"(tp={metrics.tp} fp={metrics.fp} tn={metrics.tn} fn={metrics.fn})"
    )
    if db:
        from bugbounty.orchestrator import Store

        Store(db).record_benchmark("fp-benchmark", metrics)
        console.print(f"recorded to {db}")


@app.command(name="juiceshop-eval")
def juiceshop_eval(base_url: str = "http://localhost:3000", db: str | None = None) -> None:
    """Expanded validator evaluation against a LOCAL Juice Shop sandbox."""
    from urllib.parse import urlparse

    from bugbounty.jobs.juiceshop_eval import run_eval

    host = urlparse(base_url).hostname or ""
    if host not in {"localhost", "127.0.0.1"}:
        console.print(f"[red]refusing: {host} is not the local sandbox[/]")
        raise typer.Exit(2)
    m, m_sup, rows = run_eval(base_url)
    table = Table(title="Juice Shop evaluation")
    for col in ("candidate", "class", "category", "expected", "validator", "note"):
        table.add_column(col)
    for cid, cls, cat, vulnerable, status, note, _reason in rows:
        table.add_row(cid, cls, cat, "vuln" if vulnerable else "safe", status, note)
    console.print(table)
    for cid, _cls, _cat, vulnerable, status, _note, reason in rows:
        if vulnerable and status != "confirmed":
            console.print(f"[yellow]MISS[/] {cid}: {status} -- {reason}")
    console.print(
        f"ALL ({m.tp + m.fp + m.tn + m.fn} cases): precision={m.precision:.2f} "
        f"recall={m.recall:.2f} fp_rate={m.fp_rate:.2f} "
        f"(tp={m.tp} fp={m.fp} tn={m.tn} fn={m.fn})"
    )
    console.print(
        f"SUPPORTED-only: precision={m_sup.precision:.2f} recall={m_sup.recall:.2f} "
        f"fp_rate={m_sup.fp_rate:.2f} (tp={m_sup.tp} fp={m_sup.fp} tn={m_sup.tn} fn={m_sup.fn})"
    )
    if db:
        from bugbounty.orchestrator import Store

        Store(db).record_benchmark("juiceshop-eval", m)
        console.print(f"recorded to {db}")


def _print_eval(res) -> None:
    if not res.available:
        console.print(f"[yellow]{res.target}: unavailable[/] -- {res.note}")
        return
    m, ms = res.metrics, res.metrics_supported
    table = Table(title=f"{res.target} evaluation")
    for col in ("candidate", "class", "category", "expected", "validator"):
        table.add_column(col)
    for cid, cls, cat, vulnerable, status, _note, _reason in res.rows:
        table.add_row(cid, cls, cat, "vuln" if vulnerable else "safe", status)
    console.print(table)
    console.print(
        f"{res.target}: ALL precision={m.precision:.2f} recall={m.recall:.2f} "
        f"fp_rate={m.fp_rate:.2f} (tp={m.tp} fp={m.fp} tn={m.tn} fn={m.fn}) | "
        f"SUPPORTED recall={ms.recall:.2f}"
    )


@app.command(name="eval-target")
def eval_target(name: str, db: str | None = None) -> None:
    """Grade the validator against one sandbox adapter."""
    from bugbounty.jobs.eval_targets import all_targets

    targets = all_targets()
    t = targets.get(name)
    if t is None:
        console.print(f"[red]unknown target {name!r}; have: {', '.join(targets)}[/]")
        raise typer.Exit(2)
    res = t.run()
    _print_eval(res)
    if db and res.available:
        from bugbounty.orchestrator import Store

        Store(db).record_benchmark(f"eval:{res.target}", res.metrics)
        console.print(f"recorded to {db}")


@app.command(name="eval-all")
def eval_all(db: str | None = None) -> None:
    """Grade the validator against every available sandbox adapter."""
    from bugbounty.jobs.eval_targets import all_targets

    summary = Table(title="Eval targets")
    for col in ("target", "available", "precision", "recall", "fp_rate", "tp/fp/tn/fn"):
        summary.add_column(col)
    for name, t in all_targets().items():
        res = t.run()
        if not res.available:
            summary.add_row(name, "no", "-", "-", "-", res.note)
            continue
        m = res.metrics
        summary.add_row(
            name,
            "yes",
            f"{m.precision:.2f}",
            f"{m.recall:.2f}",
            f"{m.fp_rate:.2f}",
            f"{m.tp}/{m.fp}/{m.tn}/{m.fn}",
        )
        if db:
            from bugbounty.orchestrator import Store

            Store(db).record_benchmark(f"eval:{name}", m)
    console.print(summary)


def _default_allowlist_exists() -> bool:
    return Path(DEFAULT_ALLOWLIST).exists()


if __name__ == "__main__":
    app()
