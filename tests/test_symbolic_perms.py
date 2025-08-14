# pylint: disable=missing-module-docstring,missing-function-docstring,missing-class-docstring

from __future__ import annotations

from typing import Generator

import itertools
import string
import pytest

from linux_keyring.libkeyutils import (
    _build_perm_mask,
    _PERM_FLAGS,
    _SET_SHIFT,
    keyctl_setperm_symbolic,
)

PERM_CHARS = "".join(_PERM_FLAGS.keys())  # "vrwxla"
ALL_BITS = 0
for b in _PERM_FLAGS.values():
    ALL_BITS |= b  # 0x3F

WHO_SETS = ["p", "u", "g", "o"]
OPS = ["+", "-", "="]


def bits_for_spec(spec: str) -> int:
    """Compute the 6-bit permission value for a permspec."""
    if spec == "all":
        return ALL_BITS
    bits = 0
    for ch in spec:
        bits |= _PERM_FLAGS[ch]
    return bits


def expected_mask_from_single_clause(who: str, op: str, spec: str) -> int:
    """
    Expected mask for a single clause starting from mask=0.
    For '+' or '-' from empty, the resulting per-set bits are:
      '+' -> bits, '-' -> 0, '=' -> bits.
    """
    bits = bits_for_spec(spec)
    if op == "-":
        newb = 0
    else:  # '+' or '=' from empty both yield 'bits'
        newb = bits

    mask = 0
    for w in who:
        shift = _SET_SHIFT[w]
        mask |= (newb & 0x3F) << shift
    return mask


def all_perm_subsets(include_empty: bool = False) -> Generator[str]:
    """Yield permspecs for all non-empty subsets of 'vrwxla' (and optionally the empty string)."""
    chars = PERM_CHARS
    if include_empty:
        yield ""
    for r in range(1, len(chars) + 1):
        for combo in itertools.combinations(chars, r):
            yield "".join(combo)


# ---------- Parametrized tests for all permutations (single clause) ----------

@pytest.mark.parametrize("who", WHO_SETS)
@pytest.mark.parametrize("op", OPS)
@pytest.mark.parametrize(
    "spec",
    list(all_perm_subsets(include_empty=True)) + ["all"],  # all subsets + "" + "all"
)
def test_all_single_clause_permutations(who: str, op: str, spec: str) -> None:
    """All permutations of who/op/spec as a single clause, starting from mask=0."""
    clause = f"{who}{op}{spec}"
    mask = _build_perm_mask([clause])
    expected = expected_mask_from_single_clause(who, op, spec)
    assert mask == expected, f"Clause {clause!r}: got {mask:#x}, expected {expected:#x}"


# ---------- Multi-who in a single clause ----------

@pytest.mark.parametrize("who_multi", ["pu", "pg", "ugo", "pugo"])
@pytest.mark.parametrize("op", OPS)
@pytest.mark.parametrize("spec", ["v", "rx", "l", "all", ""])
def test_multi_who_single_clause(who_multi: str, op: str, spec: str) -> None:
    clause = f"{who_multi}{op}{spec}"
    mask = _build_perm_mask([clause])
    expected = expected_mask_from_single_clause(who_multi, op, spec)
    assert mask == expected


# ---------- Default who (omitted) applies to p,u,g,o ----------

@pytest.mark.parametrize("op", OPS)
@pytest.mark.parametrize("spec", ["v", "rx", "all", ""])
def test_default_who_is_pugo(op: str, spec: str) -> None:
    clause = f"{op}{spec}"  # no who -> applies to all sets
    mask = _build_perm_mask([clause])
    expected = expected_mask_from_single_clause("pugo", op, spec)
    assert mask == expected


# ---------- Multiple clauses: order and composability ----------

def test_multiple_clauses_composition_add_then_remove() -> None:
    # Start from empty:
    # u=rx -> set u bits to rx
    # u+w  -> add w to u
    # u-x  -> remove x from u
    clauses = ["u=rx", "u+w", "u-x"]
    mask = _build_perm_mask(clauses)

    # Compute expected manually
    u_shift = _SET_SHIFT["u"]
    u_bits = bits_for_spec("rx")        # after '='
    u_bits = (u_bits | bits_for_spec("w")) & 0x3F  # after '+w'
    u_bits = u_bits & (~_PERM_FLAGS["x"] & 0x3F)  # after '-x'

    expected = u_bits << u_shift
    assert mask == expected


def test_multiple_clauses_different_sets() -> None:
    # p=all, g=rx, o+w, u-v (no-op since empty), g-l
    clauses = ["p=all", "g=rx", "o+w", "u-v", "g-l"]
    mask = _build_perm_mask(clauses)

    p_bits = ALL_BITS
    g_bits = bits_for_spec("rx")
    g_bits = g_bits & (~_PERM_FLAGS["l"] & 0x3F)
    o_bits = bits_for_spec("w")
    u_bits = 0  # '-v' from empty remains 0

    expected = (
        (p_bits << _SET_SHIFT["p"])
        | (u_bits << _SET_SHIFT["u"])  # noqa: W503
        | (g_bits << _SET_SHIFT["g"])  # noqa: W503
        | (o_bits << _SET_SHIFT["o"])  # noqa: W503
    )
    assert mask == expected


def test_order_matters() -> None:
    # g=rx then g=w (overwrites) vs g=w then g=rx (overwrites)
    m1 = _build_perm_mask(["g=rx", "g=w"])
    m2 = _build_perm_mask(["g=w", "g=rx"])
    g_shift = _SET_SHIFT["g"]
    assert m1 == (bits_for_spec("w") << g_shift)
    assert m2 == (bits_for_spec("rx") << g_shift)
    assert m1 != m2


# ---------- Whitespace and empty clauses ----------

def test_whitespace_and_empty_clauses_ignored() -> None:
    clauses = ["  u=rx  ", "", "   ", "g+v", "\t", "o+all"]
    mask = _build_perm_mask(clauses)

    expected = 0
    expected |= bits_for_spec("rx") << _SET_SHIFT["u"]
    expected |= bits_for_spec("v") << _SET_SHIFT["g"]
    expected |= ALL_BITS << _SET_SHIFT["o"]
    assert mask == expected


# ---------- Error handling ----------

@pytest.mark.parametrize("bad", ["q=rx", "p*rx", "u+rz", "g=foo", "x+v", "p", "p?"])
def test_invalid_clauses_raise(bad: str) -> None:
    with pytest.raises(ValueError):
        _build_perm_mask([bad])


@pytest.mark.parametrize("bad_perm", list(set(string.ascii_lowercase) - set(PERM_CHARS)))
def test_unknown_perm_chars_raise_each(bad_perm: str) -> None:
    with pytest.raises(ValueError):
        _build_perm_mask([f"u+{bad_perm}"])


# ---------- keyctl_setperm_symbolic wiring ----------

# pylint: disable=line-too-long
def test_keyctl_setperm_symbolic_calls_keyctl_with_expected_mask(monkeypatch: pytest.MonkeyPatch) -> None:
    called = {}

    def fake_keyctl_setperm(key: int, mask: int) -> None:
        called["key"] = key
        called["mask"] = mask

    # Patch the symbol in the module under test
    # pylint: disable=import-outside-toplevel
    import linux_keyring.libkeyutils as mod
    monkeypatch.setattr(mod, "keyctl_setperm", fake_keyctl_setperm)

    key = 12345
    spec = "u=rx, g+w, o-all, p-l"
    keyctl_setperm_symbolic(key, spec)

    # Compute expected for the combined spec
    expected = _build_perm_mask(spec.split(","))
    assert called == {"key": key, "mask": expected}
