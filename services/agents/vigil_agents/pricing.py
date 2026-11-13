"""USD per 1M tokens (input, output). Used for budget enforcement and cost accounting.

Each model has a list of (effective_from, input, output) entries; the latest entry whose date has
started applies. A model with no entry is refused (see `require_price`) so a run can never execute
with its cost budget silently disabled. Prices checked 2026-11-12 against the vendors' pricing pages.
"""
from __future__ import annotations

from datetime import date

PRICES: dict[str, list[tuple[date, float, float]]] = {
    "claude-fable-5-1": [(date(2000, 1, 1), 10.0, 50.0)],
    "claude-opus-5-5": [(date(2000, 1, 1), 4.0, 20.0)],
    "claude-sonnet-5-5": [(date(2000, 1, 1), 2.0, 10.0)],
    "claude-haiku-5-5": [(date(2000, 1, 1), 0.10, 0.50)],
    # Gemini output price includes thinking tokens. Introductory prices end on the dates below.
    "gemini-4-argon": [(date(2000, 1, 1), 2.0, 10.0), (date(2026, 12, 1), 4.0, 20.0)],
    "gemini-4-carbon": [(date(2000, 1, 1), 2.0, 10.0), (date(2026, 12, 1), 4.0, 20.0)],
    "gemini-3.8-flash": [(date(2000, 1, 1), 0.75, 3.75), (date(2027, 1, 1), 1.50, 7.50)],
}

UNPRICED_OK = {"test-script"}  # scripted provider (tests/eval only)


def _rate(model: str, today: date | None = None) -> tuple[float, float] | None:
    entries = PRICES.get(model)
    if not entries:
        return None
    today = today or date.today()
    cur = None
    for since, pin, pout in sorted(entries):
        if since <= today:
            cur = (pin, pout)
    return cur


def require_price(model: str) -> None:
    """Fail closed: refuse to run a model whose cost cannot be computed."""
    if model not in UNPRICED_OK and _rate(model) is None:
        raise ValueError(f"no price configured for model '{model}' - add it to pricing.PRICES before use")


def cost_usd(model: str, input_tokens: int, output_tokens: int, today: date | None = None) -> float:
    rate = _rate(model, today)
    if rate is None:
        return 0.0
    pin, pout = rate
    return (input_tokens * pin + output_tokens * pout) / 1_000_000
