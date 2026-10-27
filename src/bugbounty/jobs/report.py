"""Nightly report: findings, sandbox precision/recall, and spend vs the credit
window (with 50/75/90% warnings)."""

from __future__ import annotations

from ..orchestrator.budget import CreditWindow
from ..orchestrator.store import Store


def build_report(store: Store, credit: CreditWindow | None = None) -> str:
    credit = credit or CreditWindow.from_env()
    counts = store.status_counts()
    total = store.total_spend_usd()
    lines = ["# bugbounty nightly report", "", "## Findings by status"]
    for k in ("confirmed", "rejected", "unconfirmed"):
        lines.append(f"- {k}: {counts.get(k, 0)}")

    b = store.latest_benchmark()
    if b is not None:
        lines += [
            "",
            "## Sandbox benchmark (latest)",
            f"- {b['name']}: precision {b['precision']:.2f} · recall {b['recall']:.2f} "
            f"· fp_rate {b['fp_rate']:.2f} (tp={b['tp']} fp={b['fp']} tn={b['tn']} fn={b['fn']})",
        ]

    lines += ["", "## Spend", f"- total: ${total:.2f}"]
    if credit.cap_usd > 0:
        pct = total / credit.cap_usd
        lines.append(f"- credit window: ${total:.2f} / ${credit.cap_usd:.2f} ({pct * 100:.0f}%)")
        for th in sorted(credit.thresholds):
            if pct >= th:
                lines.append(f"  - WARNING: crossed {int(th * 100)}% of the credit window")
        if total > credit.cap_usd:
            lines.append("  - WARNING: OVER the credit cap — stop overnight batches")
    for target, amt in sorted(store.spend_by_target().items()):
        lines.append(f"- {target}: ${amt:.2f}")
    return "\n".join(lines) + "\n"
