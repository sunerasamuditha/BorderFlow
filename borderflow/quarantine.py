from __future__ import annotations

import re
from decimal import Decimal
from typing import Any

_NUM = r"([0-9]+(?:\.[0-9]+)?)"


def _text(content: Any) -> str:
    if isinstance(content, dict):
        return " ".join(f"{k}: {v}" for k, v in content.items())
    return str(content)


def price(content: Any) -> Decimal:
    if isinstance(content, dict) and "price" in content:
        return Decimal(str(content["price"])).quantize(Decimal("0.01"))
    m = re.search(r"price\s*[:=]\s*" + _NUM, _text(content), re.I)
    if not m:
        raise ValueError("no price")
    return Decimal(m.group(1)).quantize(Decimal("0.01"))


def lead_time_days(content: Any) -> int:
    if isinstance(content, dict) and "lead_time_days" in content:
        return int(content["lead_time_days"])
    m = re.search(r"lead[_ ]time\s*[:=]\s*([0-9]+)", _text(content), re.I)
    if not m:
        raise ValueError("no lead time")
    return int(m.group(1))


def skill_tags(content: Any) -> tuple:
    return tuple(sorted(set(re.findall(r"\b(quote|pumps|valves|logistics|delivery)\b", _text(content).lower()))))


def pickup_date(content: Any) -> str:
    m = re.search(r"(20[0-9]{2}-[01][0-9]-[0-3][0-9])", _text(content))
    if not m:
        raise ValueError("no date")
    return m.group(1)
