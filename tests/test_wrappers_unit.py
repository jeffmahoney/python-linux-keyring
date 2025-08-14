# pylint: disable=missing-module-docstring,missing-function-docstring,missing-class-docstring
# mypy: disable-error-code="func-returns-value"
from typing import Optional, Tuple, Any, Callable, List

import pytest

import linux_keyring.libkeyutils as ku

SUPPORTED_OPS = 1234
KEY_SIZE = 12345
DATA_SIZE = 123456
SIG_SIZE = 1234567
ENC_SIZE = 12345678
DEC_SIZE = 123456789


class FakeCK:
    def __init__(self) -> None:
        self.calls: list[Tuple] = []
        self.keyctl_update: Callable

    # define minimal methods used by wrappers (subset)
    def add_key(self, t: str, d: str, p: ku.KeyPayload,
                kr: ku.key_serial_t) -> ku.key_serial_t:
        self.calls.append(("add_key", t, d, p, kr))
        return 42

    def keyctl_join_session_keyring(self, name: Optional[str]) -> ku.key_serial_t:
        self.calls.append(("join_session_keyring", name))
        return 42

    def keyctl_describe(self, key: ku.key_serial_t) -> str:
        self.calls.append(("describe", key))
        return "user;desc;perm"

    # pylint: disable=too-many-arguments,too-many-positional-arguments
    def keyctl_dh_compute_kdf(self, priv: ku.key_serial_t,
                              prime: ku.key_serial_t, base: ku.key_serial_t,
                              hashname: str, otherinfo: Optional[bytes],
                              outlen: ku.key_serial_t) -> bytes:
        self.calls.append(("dh_compute_kdf", priv, prime, base, hashname,
                           otherinfo, outlen))
        return b"data"

    def keyctl_get_security(self, key: ku.key_serial_t) -> str:
        self.calls.append(("get_security", key))
        return "system_u:object_r:key_t:s0"

    def keyctl_instantiate(self, k: ku.key_serial_t, p: ku.KeyPayload, kr: ku.key_serial_t) -> None:
        self.calls.append(("instantiate", k, p, kr))

    def keyctl_instantiate_iov(self, k: ku.key_serial_t, iov: Optional[List[ku.KeyPayload]],
                               kr: ku.key_serial_t) -> None:
        self.calls.append(("instantiate_iov", k, iov, kr))

    def keyctl_pkey_decrypt(self, k: ku.key_serial_t, i: str, d: bytes, o: int) -> bytes:
        self.calls.append(("pkey_decrypt", k, i, d, o))
        return b"decrypted-data"

    def keyctl_pkey_encrypt(self, k: ku.key_serial_t, i: str, d: bytes, o: int) -> bytes:
        self.calls.append(("pkey_encrypt", k, i, d, o))
        return b"encrypted-data"

    def keyctl_pkey_query(self, k: ku.key_serial_t,
                          i: str) -> Tuple[int, int, int, int, int, int]:
        self.calls.append(("pkey_query", k, i))
        return (SUPPORTED_OPS, KEY_SIZE, DATA_SIZE, SIG_SIZE, ENC_SIZE, DEC_SIZE)

    def keyctl_pkey_sign(self, k: ku.key_serial_t, i: str, d: bytes, o: int) -> bytes:
        self.calls.append(("pkey_sign", k, i, d, o))
        return b"signature"

    def keyctl_pkey_verify(self, k: ku.key_serial_t, i: str, d: bytes, s: bytes) -> None:
        self.calls.append(("pkey_verify", k, i, d, s))

    def keyctl_restrict_keyring(self, kr: ku.key_serial_t, typ: Optional[str],
                                restr: Optional[str]) -> None:
        self.calls.append(("restrict", kr, typ, restr))

    def keyctl_read(self, key: ku.key_serial_t) -> bytes:
        self.calls.append(("read", key))
        return b"payload"

    def keyctl_search(self, kr: ku.key_serial_t, t: str, d: str,
                      dkr: ku.key_serial_t) -> ku.key_serial_t:
        self.calls.append(("search", kr, t, d, dkr))
        return 42

    def keyctl_move(self, key: ku.key_serial_t, fr: ku.key_serial_t,
                    to: ku.key_serial_t, flags: int) -> None:
        self.calls.append(("move", key, fr, to, flags))

    def request_key(self, t: str, d: str, callout_info: str,
                    kr: ku.key_serial_t) -> ku.key_serial_t:
        self.calls.append(("request_key", t, d, callout_info, kr))
        return 42


def test_add_key_none_payload(monkeypatch: Any) -> None:
    fake = FakeCK()
    monkeypatch.setattr(ku, "api", fake, raising=False)
    ret = ku.add_key("user", "desc", None, 123)
    assert ret == 42
    assert fake.calls[0] == ("add_key", b"user", b"desc", None, 123)


def test_add_key_str_payload(monkeypatch: Any) -> None:
    fake = FakeCK()
    monkeypatch.setattr(ku, "api", fake, raising=False)
    ret = ku.add_key("user", "desc", "payload", 123)
    assert ret == 42
    assert fake.calls[0] == ("add_key", b"user", b"desc", b"payload", 123)


def test_add_key_bytes_payload(monkeypatch: Any) -> None:
    fake = FakeCK()
    monkeypatch.setattr(ku, "api", fake, raising=False)
    ret = ku.add_key("user", "desc", b"payload", 123)
    assert ret == 42
    assert fake.calls[0] == ("add_key", b"user", b"desc", b"payload", 123)


def test_dh_compute_kdf_none_otherinfo(monkeypatch: Any) -> None:
    fake = FakeCK()
    monkeypatch.setattr(ku, "api", fake, raising=False)
    ret = ku.keyctl_dh_compute_kdf(121, 122, 123, "hash", None, 124)
    assert ret == b"data"
    assert fake.calls[0] == ("dh_compute_kdf", 121, 122, 123, b"hash", None, 124)


def test_dh_compute_kdf_bytes_otherinfo(monkeypatch: Any) -> None:
    fake = FakeCK()
    monkeypatch.setattr(ku, "api", fake, raising=False)
    ret = ku.keyctl_dh_compute_kdf(121, 122, 123, "hash", b"otherinfo", 124)
    assert ret == b"data"
    assert fake.calls[0] == ("dh_compute_kdf", 121, 122, 123, b"hash", b"otherinfo", 124)


def test_dh_compute_kdf_none_otherinfo_5args(monkeypatch: Any) -> None:
    fake = FakeCK()
    monkeypatch.setattr(ku, "api", fake, raising=False)
    ret = ku.keyctl_dh_compute_kdf(121, 122, 123, "hash", None)
    print(fake.calls)
    assert ret == b"data"
    assert fake.calls[0] == ("dh_compute_kdf", 121, 122, 123, b"hash", None, 0)


def test_dh_compute_kdf_bytes_otherinfo_5args(monkeypatch: Any) -> None:
    fake = FakeCK()
    monkeypatch.setattr(ku, "api", fake, raising=False)
    ret = ku.keyctl_dh_compute_kdf(121, 122, 123, "hash", b"otherinfo")
    assert ret == b"data"
    assert fake.calls[0] == ("dh_compute_kdf", 121, 122, 123, b"hash", b"otherinfo", 0)


def test_dh_compute_kdf_4args(monkeypatch: Any) -> None:
    fake = FakeCK()
    monkeypatch.setattr(ku, "api", fake, raising=False)
    ret = ku.keyctl_dh_compute_kdf(121, 122, 123, "hash")
    assert ret == b"data"
    assert fake.calls[0] == ("dh_compute_kdf", 121, 122, 123, b"hash", None, 0)


def test_instantiate_none_payload(monkeypatch: Any) -> None:
    fake = FakeCK()
    monkeypatch.setattr(ku, "api", fake, raising=False)
    assert ku.keyctl_instantiate(122, None, 123) is None
    assert fake.calls[0] == ("instantiate", 122, None, 123)


def test_instantiate_str_payload(monkeypatch: Any) -> None:
    fake = FakeCK()
    monkeypatch.setattr(ku, "api", fake, raising=False)
    assert ku.keyctl_instantiate(122, "payload", 123) is None
    assert fake.calls[0] == ("instantiate", 122, b"payload", 123)


def test_instantiate_bytes_payload(monkeypatch: Any) -> None:
    fake = FakeCK()
    monkeypatch.setattr(ku, "api", fake, raising=False)
    assert ku.keyctl_instantiate(122, b"payload", 123) is None
    assert fake.calls[0] == ("instantiate", 122, b"payload", 123)


def test_instantiate_iov_none_payload(monkeypatch: Any) -> None:
    fake = FakeCK()
    monkeypatch.setattr(ku, "api", fake, raising=False)
    assert ku.keyctl_instantiate_iov(122, None, 123) is None
    assert fake.calls[0] == ("instantiate_iov", 122, None, 123)


def test_instantiate_iov_str_payload(monkeypatch: Any) -> None:
    fake = FakeCK()
    monkeypatch.setattr(ku, "api", fake, raising=False)
    assert ku.keyctl_instantiate_iov(122, ["payload1", "payload2"], 123) is None
    assert fake.calls[0] == ("instantiate_iov", 122, [b"payload1", b"payload2"], 123)


def test_instantiate_iov_bytes_payload(monkeypatch: Any) -> None:
    fake = FakeCK()
    monkeypatch.setattr(ku, "api", fake, raising=False)
    assert ku.keyctl_instantiate_iov(122, [b"payload1", b"payload2"], 123) is None
    assert fake.calls[0] == ("instantiate_iov", 122, [b"payload1", b"payload2"], 123)


def test_join_session_keyring_none(monkeypatch: Any) -> None:
    fake = FakeCK()
    monkeypatch.setattr(ku, "api", fake, raising=False)
    ret = ku.keyctl_join_session_keyring(None)
    assert ret == 42
    assert fake.calls[0] == ("join_session_keyring", None)


def test_join_session_keyring_name(monkeypatch: Any) -> None:
    fake = FakeCK()
    monkeypatch.setattr(ku, "api", fake, raising=False)
    assert ku.keyctl_join_session_keyring("name") == 42
    assert fake.calls[0] == ("join_session_keyring", b"name")


def test_pkey_decrypt(monkeypatch: Any) -> None:
    fake = FakeCK()
    monkeypatch.setattr(ku, "api", fake, raising=False)
    assert ku.keyctl_pkey_decrypt(121, "info", b"data", 122) == b"decrypted-data"
    assert fake.calls[0] == ("pkey_decrypt", 121, b"info", b"data", 122)


def test_pkey_decrypt_3arg_zero_size(monkeypatch: Any) -> None:
    fake = FakeCK()
    monkeypatch.setattr(ku, "api", fake, raising=False)
    assert ku.keyctl_pkey_decrypt(121, "info", b"data") == b"decrypted-data"
    assert fake.calls[0] == ("pkey_query", 121, b"info")
    assert fake.calls[1] == ("pkey_decrypt", 121, b"info", b"data", DEC_SIZE)


def test_pkey_decrypt_3arg(monkeypatch: Any) -> None:
    fake = FakeCK()
    monkeypatch.setattr(ku, "api", fake, raising=False)
    assert ku.keyctl_pkey_decrypt(121, "info", b"data") == b"decrypted-data"
    assert fake.calls[0] == ("pkey_query", 121, b"info")
    assert fake.calls[1] == ("pkey_decrypt", 121, b"info", b"data", DEC_SIZE)


def test_pkey_encrypt(monkeypatch: Any) -> None:
    fake = FakeCK()
    monkeypatch.setattr(ku, "api", fake, raising=False)
    assert ku.keyctl_pkey_encrypt(121, "info", b"data", 122) == b"encrypted-data"
    assert fake.calls[0] == ("pkey_encrypt", 121, b"info", b"data", 122)


def test_pkey_encrypt_3arg_zero_size(monkeypatch: Any) -> None:
    fake = FakeCK()
    monkeypatch.setattr(ku, "api", fake, raising=False)
    assert ku.keyctl_pkey_encrypt(121, "info", b"data") == b"encrypted-data"
    assert fake.calls[0] == ("pkey_query", 121, b"info")
    assert fake.calls[1] == ("pkey_encrypt", 121, b"info", b"data", ENC_SIZE)


def test_pkey_encrypt_3arg(monkeypatch: Any) -> None:
    fake = FakeCK()
    monkeypatch.setattr(ku, "api", fake, raising=False)
    assert ku.keyctl_pkey_encrypt(121, "info", b"data") == b"encrypted-data"
    assert fake.calls[0] == ("pkey_query", 121, b"info")
    assert fake.calls[1] == ("pkey_encrypt", 121, b"info", b"data", ENC_SIZE)


def test_pkey_query(monkeypatch: Any) -> None:
    fake = FakeCK()
    monkeypatch.setattr(ku, "api", fake, raising=False)
    d = {
        "supported_ops": SUPPORTED_OPS,
        "key_size":      KEY_SIZE,
        "max_data_size": DATA_SIZE,
        "max_sig_size":  SIG_SIZE,
        "max_enc_size":  ENC_SIZE,
        "max_dec_size":  DEC_SIZE,
    }

    assert ku.keyctl_pkey_query(123, "info") == d
    assert fake.calls[0] == ("pkey_query", 123, b"info")


def test_pkey_sign(monkeypatch: Any) -> None:
    fake = FakeCK()
    monkeypatch.setattr(ku, "api", fake, raising=False)
    assert ku.keyctl_pkey_sign(121, "info", b"data", 122) == b"signature"
    assert fake.calls[0] == ("pkey_sign", 121, b"info", b"data", 122)


def test_pkey_sign_3arg_zero_size(monkeypatch: Any) -> None:
    fake = FakeCK()
    monkeypatch.setattr(ku, "api", fake, raising=False)
    assert ku.keyctl_pkey_sign(121, "info", b"data") == b"signature"
    assert fake.calls[0] == ("pkey_query", 121, b"info")
    assert fake.calls[1] == ("pkey_sign", 121, b"info", b"data", SIG_SIZE)


def test_pkey_sign_3arg(monkeypatch: Any) -> None:
    fake = FakeCK()
    monkeypatch.setattr(ku, "api", fake, raising=False)
    assert ku.keyctl_pkey_sign(121, "info", b"data") == b"signature"
    assert fake.calls[0] == ("pkey_query", 121, b"info")
    assert fake.calls[1] == ("pkey_sign", 121, b"info", b"data", SIG_SIZE)


def test_pkey_verify(monkeypatch: Any) -> None:
    fake = FakeCK()
    monkeypatch.setattr(ku, "api", fake, raising=False)
    assert ku.keyctl_pkey_verify(121, "info", b"data", b"signature") is None
    assert fake.calls[0] == ("pkey_verify", 121, b"info", b"data", b"signature")


def test_request_key_none_callout(monkeypatch: Any) -> None:
    fake = FakeCK()
    monkeypatch.setattr(ku, "api", fake, raising=False)
    assert ku.request_key("user", "desc", None, 123) == 42
    assert fake.calls[0] == ("request_key", b"user", b"desc", None, 123)


def test_restrict_keyring_none(monkeypatch: Any) -> None:
    fake = FakeCK()
    monkeypatch.setattr(ku, "api", fake, raising=False)
    assert ku.keyctl_restrict_keyring(1, None, None) is None
    assert fake.calls[0] == ("restrict", 1, None, None)


def test_restrict_keyring_str(monkeypatch: Any) -> None:
    fake = FakeCK()
    monkeypatch.setattr(ku, "api", fake, raising=False)
    assert ku.keyctl_restrict_keyring(1, "type", "restriction") is None
    assert fake.calls[0] == ("restrict", 1, b"type", b"restriction")


def test_read(monkeypatch: Any) -> None:
    fake = FakeCK()
    monkeypatch.setattr(ku, "api", fake, raising=False)
    assert ku.keyctl_read(9) == b"payload"
    assert fake.calls[0] == ("read", 9)


def test_describe(monkeypatch: Any) -> None:
    fake = FakeCK()
    monkeypatch.setattr(ku, "api", fake, raising=False)
    assert ku.keyctl_describe(9) == "user;desc;perm"
    assert fake.calls[0] == ("describe", 9)


def test_get_security(monkeypatch: Any) -> None:
    fake = FakeCK()
    monkeypatch.setattr(ku, "api", fake, raising=False)
    assert ku.keyctl_get_security(9) == "system_u:object_r:key_t:s0"
    assert fake.calls[0] == ("get_security", 9)


def test_read_as_str(monkeypatch: Any) -> None:
    fake = FakeCK()
    monkeypatch.setattr(ku, "api", fake, raising=False)
    assert ku.keyctl_read_as_str(9) == "payload"
    assert fake.calls[0] == ("read", 9)


def test_search(monkeypatch: Any) -> None:
    fake = FakeCK()
    monkeypatch.setattr(ku, "api", fake, raising=False)
    assert ku.keyctl_search(1, "type", "desc", 2) == 42
    assert fake.calls[0] == ("search", 1, b"type", b"desc", 2)


def test_move_default_flags(monkeypatch: Any) -> None:
    fake = FakeCK()
    monkeypatch.setattr(ku, "api", fake, raising=False)
    assert ku.keyctl_move(1, 2, 3) is None
    assert fake.calls[0] == ("move", 1, 2, 3, 0)


def test_update_error_propagates(monkeypatch: Any) -> None:
    fake = FakeCK()

    def boom(key: ku.key_serial_t, payload: bytes) -> None:
        raise OSError(1, "perm")

    fake.keyctl_update = boom
    monkeypatch.setattr(ku, "api", fake, raising=False)
    with pytest.raises(OSError):
        ku.keyctl_update(1, b"x")
