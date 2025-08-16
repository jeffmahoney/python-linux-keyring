# pylint: disable=missing-module-docstring,missing-function-docstring,missing-class-docstring

import os
import time
import errno
import platform

from typing import Generator

import pytest

import linux_keyring.libkeyutils as ku


def _linux_only() -> bool:
    return platform.system() == "Linux" and os.path.exists("/proc")


pytestmark = pytest.mark.skipif(not _linux_only(), reason="Linux keyrings required")


@pytest.fixture(name="session_kr")
def generate_session_kr() -> Generator[ku.key_serial_t, None, None]:
    '''
    Create/join an isolated session keyring for each test and ensure cleanup.
    '''
    name = f"pytest-keyutils-{os.getpid()}-{time.time_ns()}"
    kr = ku.keyctl_join_session_keyring(name)
    assert isinstance(kr, int) and kr != 0
    try:
        yield kr
    finally:
        # best-effort cleanup
        try:
            ku.keyctl_clear(kr)
        except OSError:
            pass


def test_join_session_keyring_and_get_id(session_kr: Generator[ku.key_serial_t, None, None]) -> None:  # pylint: disable=unused-argument,line-too-long
    rid = ku.keyctl_get_keyring_ID(ku.api.KEY_SPEC_SESSION_KEYRING, 0)
    assert isinstance(rid, int) and rid != 0


def test_add_read_update_describe(session_kr: ku.key_serial_t) -> None:
    key = ku.add_key("user", "py-ku-desc", b"payload", session_kr)
    assert key > 0

    data = ku.keyctl_read(key)
    assert data == b"payload"

    ku.keyctl_update(key, "newdata")
    assert ku.keyctl_read(key) == b"newdata"

    desc = ku.keyctl_describe(key)
    assert isinstance(desc, str) and len(desc) > 0
    assert "py-ku-desc" in desc


def test_request_key_finds_existing(session_kr: ku.key_serial_t) -> None:
    desc = "req-demo"
    key = ku.add_key("user", desc, "v", session_kr)
    got = ku.request_key("user", desc, None, session_kr)
    assert got == key


def test_get_security_supported_or_skip(session_kr: ku.key_serial_t) -> None:
    key = ku.add_key("user", "sec-demo", "x", session_kr)
    try:
        ctx = ku.keyctl_get_security(key)
    except OSError as e:
        if e.errno in (errno.EOPNOTSUPP, errno.ENOSYS):
            pytest.skip("security labels not supported")
        raise
    assert isinstance(ctx, str)


def test_capabilities_supported_or_skip() -> None:
    try:
        caps = ku.keyctl_capabilities()
    except OSError as e:
        if e.errno in (errno.EOPNOTSUPP, errno.ENOSYS):
            pytest.skip("capabilities not supported")
        raise
    assert isinstance(caps, (bytes, bytearray))


def test_link_unlink_clear(session_kr: ku.key_serial_t) -> None:
    # make a child keyring
    child = ku.add_key("keyring", "child", "", session_kr)
    key = ku.add_key("user", "link-demo", "data", session_kr)

    # link into child
    ku.keyctl_link(key, child)

    # unlink once -> ok
    ku.keyctl_unlink(key, child)

    # unlink again -> should error
    with pytest.raises(OSError):
        ku.keyctl_unlink(key, child)

    # link again and then clear the keyring
    ku.keyctl_link(key, child)
    ku.keyctl_clear(child)

    with pytest.raises(OSError):
        ku.keyctl_search(child, "user", "link-demo", 0)


def test_move_between_keyrings(session_kr: ku.key_serial_t) -> None:
    a = ku.add_key("keyring", "A", "", session_kr)
    b = ku.add_key("keyring", "B", "", session_kr)
    k = ku.add_key("user", "moved", "d", session_kr)

    # link to A
    ku.keyctl_link(k, a)
    # move to B
    ku.keyctl_move(k, a, b)

    # now present in B
    found = ku.keyctl_search(b, "user", "moved", 0)
    assert found == k

    # and absent in A
    with pytest.raises(OSError):
        ku.keyctl_search(a, "user", "moved", 0)


def test_search_in_session(session_kr: ku.key_serial_t) -> None:
    k = ku.add_key("user", "s1", "x", session_kr)
    got = ku.keyctl_search(session_kr, "user", "s1", 0)
    assert got == k


def test_invalidate_and_revoke(session_kr: ku.key_serial_t) -> None:
    k1 = ku.add_key("user", "invalid", "x", session_kr)
    ku.keyctl_invalidate(k1)
    with pytest.raises(OSError):
        ku.keyctl_read(k1)

    k2 = ku.add_key("user", "revoked", "x", session_kr)
    ku.keyctl_revoke(k2)
    with pytest.raises(OSError):
        ku.keyctl_read(k2)


def test_setperm_symbolic_and_setperm(session_kr: ku.key_serial_t) -> None:
    k = ku.add_key("user", "perm", "x", session_kr)
    # symbolic helper should exist and call numeric setperm underneath
    ku.keyctl_setperm_symbolic(k, "u=vrwlxa,g=,o=")  # owner full, others none
    # Also exercise raw numeric path with a plausible mask (owner view+read)
    mask = ku.api.KEY_USR_VIEW | ku.api.KEY_USR_READ
    ku.keyctl_setperm(k, mask)


def test_set_timeout_expire(session_kr: ku.key_serial_t) -> None:
    k = ku.add_key("user", "exp", "x", session_kr)
    ku.keyctl_set_timeout(k, 1)
    time.sleep(1.5)
    with pytest.raises(OSError):
        ku.keyctl_read(k)


def test_chown_same_ids(session_kr: ku.key_serial_t) -> None:
    k = ku.add_key("user", "own", "x", session_kr)
    uid, gid = os.getuid(), os.getgid()
    # Changing to the same UID/GID should succeed for the owner
    ku.keyctl_chown(k, uid, gid)


def test_restrict_keyring_reject(session_kr: ku.key_serial_t) -> None:
    child = ku.add_key("keyring", "restricted", "", session_kr)
    # Restrict to reject all future links
    ku.keyctl_restrict_keyring(child, None, None)
    k = ku.add_key("user", "rkey", "x", session_kr)
    with pytest.raises(OSError):
        ku.keyctl_link(k, child)


def test_get_persistent(session_kr: ku.key_serial_t) -> None:
    # Link persistent keyring into our session for convenience
    pk = ku.keyctl_get_persistent(os.getuid(), session_kr)
    assert isinstance(pk, int) and pk != 0


def test_aliases(session_kr: ku.key_serial_t) -> None:
    k = ku.add_key("user", "alias", "x", session_kr)
    assert ku.keyctl_read(k) == b"x"
    assert isinstance(ku.keyctl_describe(k), str)

    try:
        _ = ku.keyctl_get_security(k)
    except OSError as e:
        if e.errno in (errno.EOPNOTSUPP, errno.ENOSYS):
            pytest.skip("security labels not supported")
        raise
