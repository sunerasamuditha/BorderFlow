from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Optional


def _fs(items: Optional[Iterable[str]]) -> Optional[frozenset]:
    return None if items is None else frozenset(items)


@dataclass(frozen=True)
class Label:
    readers: Optional[frozenset]
    writers: frozenset

    @staticmethod
    def of(readers: Optional[Iterable[str]] = None, writers: Iterable[str] = ()) -> "Label":
        return Label(_fs(readers), frozenset(writers))

    def join(self, other: "Label") -> "Label":
        if self.readers is None:
            readers = other.readers
        elif other.readers is None:
            readers = self.readers
        else:
            readers = self.readers & other.readers
        return Label(readers, self.writers | other.writers)

    __or__ = join

    def flows_to(self, other: "Label") -> bool:
        if self.readers is None:
            readers_ok = True
        elif other.readers is None:
            readers_ok = False
        else:
            readers_ok = self.readers >= other.readers
        return readers_ok and self.writers <= other.writers

    __le__ = flows_to

    def can_read(self, principal: str) -> bool:
        return self.readers is None or principal in self.readers

    def readers_include(self, principals: Iterable[str]) -> bool:
        return all(self.can_read(p) for p in principals)

    def to_json(self) -> dict:
        return {
            "r": "*" if self.readers is None else sorted(self.readers),
            "w": sorted(self.writers),
        }

    @staticmethod
    def from_json(obj: dict) -> "Label":
        r = obj.get("r", "*")
        return Label(None if r == "*" else frozenset(r), frozenset(obj.get("w", [])))

    def __str__(self) -> str:
        r = "*" if self.readers is None else "{" + ",".join(sorted(self.readers)) + "}"
        w = "{" + ",".join(sorted(self.writers)) + "}"
        return f"<R={r}, W={w}>"


BOTTOM = Label(None, frozenset())


def join_all(labels: Iterable[Label]) -> Label:
    out = BOTTOM
    for label in labels:
        out = out.join(label)
    return out


def writer(principal: str) -> Label:
    return Label(None, frozenset({principal}))
