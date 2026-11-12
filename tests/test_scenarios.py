import asyncio

import pytest

from experiments.attacks import ATTACKS, run_attack
from experiments.plans import TASKS, run_task

EXPECTED_UNILATERAL_SUCCESS = {"tamper", "cross_client"}


@pytest.mark.parametrize("kind", [a[0] for a in ATTACKS])
def test_attacks_succeed_without_borderflow(kind):
    assert asyncio.run(run_attack(kind, "none")).success


@pytest.mark.parametrize("kind", [a[0] for a in ATTACKS])
def test_attacks_blocked_by_borderflow(kind):
    uni = asyncio.run(run_attack(kind, "borderflow", bilateral=False)).success
    bi = asyncio.run(run_attack(kind, "borderflow", bilateral=True)).success
    assert uni == (kind in EXPECTED_UNILATERAL_SUCCESS)
    assert not bi


def test_benign_tasks():
    results = [asyncio.run(run_task(fn)) for fn in TASKS]
    assert results[0].completed and results[0].autonomous
    assert results[1].completed and results[1].autonomous
    assert results[2].completed and results[2].endorsements == 1
    assert not results[3].completed and results[3].declassifications == 1
