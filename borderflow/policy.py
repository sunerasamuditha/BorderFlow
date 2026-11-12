from __future__ import annotations

import math
from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation
from typing import Any, Callable, Iterable, Optional

from .labels import Label


class FiniteType:
    name = "finite"

    def validate(self, value: Any) -> bool:
        raise NotImplementedError

    def domain_size(self) -> int:
        raise NotImplementedError

    def bits(self) -> float:
        return math.log2(max(self.domain_size(), 1))


@dataclass(frozen=True)
class EnumType(FiniteType):
    values: tuple

    @property
    def name(self) -> str:
        return "enum{" + ",".join(map(str, self.values)) + "}"

    def validate(self, value: Any) -> bool:
        return value in self.values

    def domain_size(self) -> int:
        return len(self.values)


@dataclass(frozen=True)
class BoundedDecimal(FiniteType):
    low: Decimal
    high: Decimal
    step: Decimal = Decimal("0.01")

    @property
    def name(self) -> str:
        return f"decimal[{self.low},{self.high}]"

    def validate(self, value: Any) -> bool:
        try:
            d = Decimal(str(value))
        except (InvalidOperation, ValueError):
            return False
        if not d.is_finite():
            return False
        return self.low <= d <= self.high and (d - self.low) % self.step == 0

    def domain_size(self) -> int:
        return int((self.high - self.low) / self.step) + 1


@dataclass(frozen=True)
class BoundedInt(FiniteType):
    low: int
    high: int

    @property
    def name(self) -> str:
        return f"int[{self.low},{self.high}]"

    def validate(self, value: Any) -> bool:
        return isinstance(value, int) and not isinstance(value, bool) and self.low <= value <= self.high

    def domain_size(self) -> int:
        return self.high - self.low + 1


@dataclass(frozen=True)
class BoolType(FiniteType):
    @property
    def name(self) -> str:
        return "bool"

    def validate(self, value: Any) -> bool:
        return isinstance(value, bool)

    def domain_size(self) -> int:
        return 2


BOOL = BoolType()


@dataclass
class Sink:
    name: str
    trust: frozenset
    audience: Callable[[dict], frozenset]
    exempt: dict = field(default_factory=dict)
    pc_exempt_types: tuple = ()
    effect: Optional[Callable[[dict], Any]] = None

    @staticmethod
    def make(
        name: str,
        trust: Iterable[str],
        audience: Iterable[str] | Callable[[dict], Iterable[str]],
        exempt: Optional[dict] = None,
        pc_exempt_types: tuple = (),
        effect: Optional[Callable[[dict], Any]] = None,
    ) -> "Sink":
        if callable(audience):
            aud_fn = lambda args, f=audience: frozenset(f(args))
        else:
            fixed = frozenset(audience)
            aud_fn = lambda args, f=fixed: f
        return Sink(name, frozenset(trust), aud_fn, dict(exempt or {}), pc_exempt_types, effect)

    def influence_bits(self) -> float:
        return sum(t.bits() for t in self.exempt.values())


@dataclass
class Policy:
    owner: str
    sinks: dict = field(default_factory=dict)
    endorsers: frozenset = frozenset()
    trusted_initiators: frozenset = frozenset()
    ingress_restrictions: dict = field(default_factory=dict)
    data_owners: dict = field(default_factory=dict)

    def add_sink(self, sink: Sink) -> None:
        self.sinks[sink.name] = sink

    def restriction_for(self, principal: str) -> Optional[Label]:
        return self.ingress_restrictions.get(principal)
