"""Batch orchestration.

Runs candidate findings through the validator with a concurrency cap, persists
every result, meters spend, and aborts hard on a budget cap or the kill switch.
Batches are resumable (already-validated candidates are skipped) and weak targets
are abandoned early.
"""

from __future__ import annotations

import uuid
from collections import defaultdict
from collections.abc import Callable
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from dataclasses import dataclass, field

from ..config import Config
from ..scope import Allowlist
from ..validator import Candidate, Validator
from ..validator.models import ValidationResult, ValidationStatus
from .budget import BudgetExceeded, BudgetMeter, CreditWindow, KillSwitchEngaged
from .store import Store

CostFn = Callable[[ValidationResult], "tuple[float, int, int]"]


def _zero_cost(_: ValidationResult) -> tuple[float, int, int]:
    """Deterministic proofs cost ~nothing; the LLM finder supplies real costs."""
    return (0.0, 0, 0)


@dataclass
class BatchResult:
    batch_id: str
    confirmed: int = 0
    rejected: int = 0
    unconfirmed: int = 0
    out_of_scope: int = 0
    aborted: bool = False
    reason: str | None = None
    warnings: list[str] = field(default_factory=list)


class Orchestrator:
    def __init__(
        self,
        config: Config,
        store: Store,
        validator: Validator | None = None,
        credit: CreditWindow | None = None,
        kill_switch_file: str | None = None,
        cost_fn: CostFn = _zero_cost,
    ) -> None:
        self.config = config
        self.store = store
        self.validator = validator or Validator(config)
        self.credit = credit or CreditWindow.from_env()
        self.kill_switch_file = kill_switch_file
        self.cost_fn = cost_fn

    def run_batch(
        self,
        allowlist: Allowlist,
        candidates: list[Candidate],
        batch_id: str | None = None,
        resume: bool = False,
        weak_target_min_attempts: int = 8,
    ) -> BatchResult:
        batch_id = batch_id or uuid.uuid4().hex[:12]
        self.store.create_batch(batch_id)
        meter = BudgetMeter(
            self.config.budget,
            self.store,
            self.credit,
            kill_switch_file=self.kill_switch_file,
        )
        result = BatchResult(batch_id=batch_id)
        already = self.store.validated_candidate_ids(batch_id) if resume else set()

        by_target: dict[str, list[Candidate]] = defaultdict(list)
        for cand in candidates:
            by_target[cand.target_name].append(cand)

        try:
            for target_name, cands in by_target.items():
                self._run_target(
                    target_name,
                    cands,
                    allowlist,
                    batch_id,
                    meter,
                    result,
                    already,
                    weak_target_min_attempts,
                )
            self.store.set_batch_status(batch_id, "done")
        except (BudgetExceeded, KillSwitchEngaged) as exc:
            result.aborted = True
            result.reason = str(exc)
            self.store.set_batch_status(batch_id, "aborted")
        return result

    def _run_target(
        self, target_name, cands, allowlist, batch_id, meter, result, already, weak_min
    ) -> None:
        target = allowlist.target_by_name(target_name)
        run_id = uuid.uuid4().hex[:12]
        self.store.start_run(run_id, batch_id, target_name)
        if target is None:
            self.store.finish_run(run_id, "skipped", "unknown target")
            return

        pending: list[Candidate] = []
        for cand in cands:
            if cand.id in already:
                continue
            if not allowlist.decide(target_name, cand.host).allowed:
                result.out_of_scope += 1
                continue
            pending.append(cand)

        attempts = 0
        confirmed_here = 0
        stopped = False
        workers = max(1, self.config.concurrency)
        with ThreadPoolExecutor(max_workers=workers) as ex:
            pending_iter = iter(pending)
            futures: dict = {}

            def submit_next() -> bool:
                cand = next(pending_iter, None)
                if cand is None:
                    return False
                meter.check(self.config)  # raises -> abort batch
                futures[ex.submit(self.validator.validate, cand, target)] = cand
                return True

            for _ in range(workers):
                if not submit_next():
                    break

            while futures:
                done, _ = wait(list(futures), return_when=FIRST_COMPLETED)
                for fut in done:
                    cand = futures.pop(fut)
                    res = fut.result()
                    self.store.record_validation(batch_id, run_id, target_name, res)
                    usd, tok, req = self.cost_fn(res)
                    meter.record(
                        f"validate:{cand.id}", usd, tok, req, batch_id, run_id, target_name
                    )
                    result.warnings.extend(meter.new_warnings())
                    attempts += 1
                    if res.status is ValidationStatus.CONFIRMED:
                        result.confirmed += 1
                        confirmed_here += 1
                    elif res.status is ValidationStatus.REJECTED:
                        result.rejected += 1
                    else:
                        result.unconfirmed += 1
                    if not stopped and attempts >= weak_min and confirmed_here == 0:
                        stopped = True
                        self.store.finish_run(
                            run_id, "early_stop", f"weak target: 0 confirms in {attempts} attempts"
                        )
                    if not stopped:
                        submit_next()
        if not stopped:
            self.store.finish_run(run_id, "done")
