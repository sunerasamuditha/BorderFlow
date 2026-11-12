import random

from borderflow.labels import BOTTOM, Label, join_all

P = ["U", "A", "S1", "S2", "L"]


def rand_label(rng):
    readers = None if rng.random() < 0.2 else {p for p in P if rng.random() < 0.5}
    return Label.of(readers, {p for p in P if rng.random() < 0.3})


def test_join_is_commutative_associative_idempotent():
    rng = random.Random(1)
    for _ in range(500):
        a, b, c = rand_label(rng), rand_label(rng), rand_label(rng)
        assert a.join(b) == b.join(a)
        assert a.join(b).join(c) == a.join(b.join(c))
        assert a.join(a) == a


def test_order_is_partial_order_and_join_is_least_upper_bound():
    rng = random.Random(2)
    for _ in range(500):
        a, b, c = rand_label(rng), rand_label(rng), rand_label(rng)
        assert a.flows_to(a)
        if a.flows_to(b) and b.flows_to(a):
            assert a == b
        if a.flows_to(b) and b.flows_to(c):
            assert a.flows_to(c)
        j = a.join(b)
        assert a.flows_to(j) and b.flows_to(j)
        if a.flows_to(c) and b.flows_to(c):
            assert j.flows_to(c)


def test_bottom_and_readers():
    assert BOTTOM.flows_to(Label.of({"U"}, {"S2"}))
    assert BOTTOM.can_read("anyone")
    assert not Label.of({"U", "A"}).can_read("S2")
    assert join_all([Label.of({"U", "A", "S1"}), Label.of({"U", "A", "S2"})]).readers == frozenset({"U", "A"})


def test_json_round_trip():
    for label in [BOTTOM, Label.of({"U"}, {"S1", "S2"}), Label.of(None, {"L"})]:
        assert Label.from_json(label.to_json()) == label
