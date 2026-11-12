from borderflow.guard import GuardConfig
from experiments.invariants import run_trace


def test_invariants_hold_for_borderflow():
    for seed in range(300):
        assert not any(run_trace(GuardConfig(), seed).values()), seed


def test_mutants_are_caught():
    for cfg in [GuardConfig(use_exposure=False), GuardConfig(join_declarations=False), GuardConfig(context_join=False), GuardConfig(track_pc=False)]:
        assert any(any(run_trace(cfg, seed).values()) for seed in range(300))
