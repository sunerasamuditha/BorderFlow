from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

from .guard import Decision, FlowGuard, Handle

ACTION_RE = re.compile(r"ACTION:\s*([a-z_]+)\(([^)]*)\)")
ARG_RE = re.compile(r'(\w+)\s*=\s*(?:"([^"]*)"|([^,]+))')


def parse_actions(text: str) -> list:
    actions = []
    for name, raw_args in ACTION_RE.findall(text):
        args = {}
        for key, quoted, bare in ARG_RE.findall(raw_args):
            args[key] = quoted if quoted else bare.strip()
        actions.append((name, args))
    return actions


@dataclass
class Attempt:
    sink: str
    args: dict
    decision: Decision


@dataclass
class CompliantPlanner:
    guard: FlowGuard
    cid: str
    attempts: list = field(default_factory=list)

    def read(self, handles: list) -> list:
        return [str(self.guard.deref(h, self.cid)) for h in handles]

    def obey(self, handles: list) -> list:
        new = []
        for text in self.read(handles):
            for sink, raw in parse_actions(text):
                if sink not in self.guard.policy.sinks:
                    continue
                args = {k: self.guard.planner_output(self.cid, v) for k, v in raw.items()}
                decision = self.guard.invoke(sink, args, self.cid)
                attempt = Attempt(sink, raw, decision)
                self.attempts.append(attempt)
                new.append(attempt)
        return new

    def answer(self, question: Handle, knowledge: dict) -> Optional[Handle]:
        text = str(self.guard.deref(question, self.cid)).lower()
        chosen = [h for key, h in knowledge.items() if key in text]
        if not chosen:
            return None
        body = " | ".join(str(self.guard.deref(h, self.cid)) for h in chosen)
        return self.guard.planner_output(self.cid, body, note="answer")
