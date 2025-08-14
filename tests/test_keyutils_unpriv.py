# pylint: disable=missing-module-docstring,missing-function-docstring,missing-class-docstring

import pytest
import linux_keyring.libkeyutils as ku


def test_join_session_keyring_ok() -> None:
    kr = ku.keyctl_join_session_keyring("keyutils-test")
    assert isinstance(kr, int) and kr != 0


def test_add_and_read_roundtrip() -> None:
    kr = ku.keyctl_join_session_keyring("keyutils-test")
    key = ku.add_key("user", "pytest-demo", b"secret", kr)
    assert key > 0
    data = ku.keyctl_read(key)
    assert data == b"secret"


def test_describe_nonexistent_errors() -> None:
    with pytest.raises(OSError):
        ku.keyctl_describe(0)


def test_unlink_nonmember_errors() -> None:
    kr = ku.keyctl_join_session_keyring("keyutils-test")
    k = ku.add_key("user", "pytest-unlink-nonmember", b"x", kr)
    empty = ku.keyctl_join_session_keyring("keyutils-empty")
    with pytest.raises(OSError):
        ku.keyctl_unlink(k, empty)


def test_setperm_symbolic_variants() -> None:
    kr = ku.keyctl_join_session_keyring("keyutils-test")
    k = ku.add_key("user", "pytest-perm", b"x", kr)
    ku.keyctl_setperm_symbolic(k, "u+r,g-r,o-r")
    with pytest.raises(PermissionError):
        ku.keyctl_setperm_symbolic(k, "p+all,g-x")
    with pytest.raises(ValueError):
        ku.keyctl_setperm_symbolic(k, "m+r")


def test_invalidate_then_read_fails() -> None:
    kr = ku.keyctl_join_session_keyring("keyutils-test")
    k = ku.add_key("user", "pytest-inval", b"dead", kr)
    ku.keyctl_invalidate(k)
    with pytest.raises(OSError):
        ku.keyctl_read(k)


def test_search_missing_raises() -> None:
    kr = ku.keyctl_join_session_keyring("keyutils-test")
    with pytest.raises(OSError):
        ku.keyctl_search(kr, "user", "definitely-not-present", ku.KEY_SPEC_SESSION_KEYRING)


def test_get_security_nonexistent() -> None:
    with pytest.raises(OSError):
        ku.keyctl_get_security(0)
