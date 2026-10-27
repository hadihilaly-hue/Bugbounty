"""Target intake (Phase 4 fills this in).

Given pasted scope text or a scope-page URL, this will populate a ``targets.yaml``
entry and flag anything ambiguous for manual confirmation. It NEVER scrapes or
auto-ingests programs on its own — the operator pastes in the programs they choose.

Phase 0 ships only the data shape (reused from scope.Target) and a stub.
"""

from __future__ import annotations

from bugbounty.scope import Target


def parse_scope_text(text: str) -> tuple[Target | None, list[str]]:
    """Parse pasted scope text into a Target plus a list of ambiguities.

    Not implemented in Phase 0. Returns (None, [reason]) so callers fail loudly
    rather than silently ingesting an unauthorized program.
    """
    raise NotImplementedError("intake.parse_scope_text lands in Phase 4")
