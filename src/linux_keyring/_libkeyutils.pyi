from __future__ import annotations

from typing import Optional, TypeVar, NewType

import sys
if sys.version_info >= (3,10):
    from typing import TypeAlias
else:
    from typing_extensions import TypeAlias

size_t : TypeAlias = int
key_serial_t : TypeAlias = int

def add_key(type: bytes, description: bytes, payload: Optional[bytes], keyring: key_serial_t) -> int: ...
def request_key(type: bytes, description: bytes, callout_info: Optional[bytes], dest_keyring: int = 0) -> int: ...
def keyctl_read(key: key_serial_t) -> bytes: ...
def keyctl_describe(key: key_serial_t) -> str: ...
def keyctl_get_security(key: key_serial_t) -> str: ...
def keyctl_capabilities() -> bytes: ...
def keyctl_update(key: key_serial_t, payload: Optional[bytes]) -> int: ...
def keyctl_revoke(key: key_serial_t) -> int: ...
def keyctl_clear(keyring: key_serial_t) -> int: ...
def keyctl_unlink(key: key_serial_t, keyring: key_serial_t) -> int: ...
def keyctl_link(key: key_serial_t, keyring: key_serial_t) -> int: ...
def keyctl_invalidate(key: key_serial_t) -> int: ...
def keyctl_chown(key: key_serial_t, uid: int, gid: int) -> int: ...
def keyctl_setperm(key: key_serial_t, perm: int) -> int: ...
def keyctl_set_timeout(key: key_serial_t, timeout: int) -> int: ...
def keyctl_assume_authority(key: key_serial_t) -> int: ...
def keyctl_join_session_keyring(name: Optional[bytes]) -> int: ...
def keyctl_search(keyring: key_serial_t, type: bytes, description: bytes, dest_keyring: int = 0) -> int: ...
def keyctl_restrict_keyring(keyring: key_serial_t, type: Optional[bytes], restriction: Optional[bytes]) -> int: ...
def keyctl_get_keyring_ID(key: key_serial_t, create: int) -> int: ...
def keyctl_session_to_parent() -> int: ...
def keyctl_set_reqkey_keyring(which: int) -> int: ...
def keyctl_get_persistent(uid: int, keyring: key_serial_t) -> int: ...
def keyctl_move(key: key_serial_t, from_keyring: key_serial_t, to_keyring: key_serial_t, flags: int = 0) -> int: ...
def keyctl_instantiate(key: key_serial_t, payload: Optional[bytes], keyring: key_serial_t) -> int: ...
def keyctl_instantiate_iov(key: key_serial_t, iov_py: Optional[list], keyring: key_serial_t) -> int: ...
def keyctl_negate(key: key_serial_t, timeout: int, keyring: key_serial_t) -> int: ...
def keyctl_reject(key: key_serial_t, timeout: int, error: int, keyring: key_serial_t) -> int: ...
def keyctl_dh_compute(priv: int, prime: int, base: int, buflen: size_t) -> bytes: ...
def keyctl_dh_compute_alloc(priv: int, prime: int, base: int) -> bytes: ...
def keyctl_dh_compute_kdf(priv: int, prime: int, base: int, hashname: bytes, otherinfo: Optional[bytes], outlen: size_t) -> bytes: ...
def keyctl_pkey_query(key: key_serial_t, info: bytes) -> tuple: ...
def keyctl_pkey_encrypt(key: key_serial_t, info: bytes, data: bytes, outlen: size_t) -> bytes: ...
def keyctl_pkey_decrypt(key: key_serial_t, info: bytes, enc: bytes, outlen: size_t) -> bytes: ...
def keyctl_pkey_sign(key: key_serial_t, info: bytes, data: bytes, siglen: size_t) -> bytes: ...
def keyctl_pkey_verify(key: key_serial_t, info: bytes, data: bytes, sig: bytes) -> int: ...
def keyctl_watch_key(key: key_serial_t, watch_queue_fd: int, watch_id: int) -> int: ...

KEY_SPEC_THREAD_KEYRING: int
KEY_SPEC_PROCESS_KEYRING: int
KEY_SPEC_SESSION_KEYRING: int
KEY_SPEC_USER_KEYRING: int
KEY_SPEC_USER_SESSION_KEYRING: int
KEY_SPEC_GROUP_KEYRING: int
KEY_SPEC_REQKEY_AUTH_KEY: int
KEY_REQKEY_DEFL_NO_CHANGE: int
KEY_REQKEY_DEFL_DEFAULT: int
KEY_REQKEY_DEFL_THREAD_KEYRING: int
KEY_REQKEY_DEFL_PROCESS_KEYRING: int
KEY_REQKEY_DEFL_SESSION_KEYRING: int
KEY_REQKEY_DEFL_USER_KEYRING: int
KEY_REQKEY_DEFL_USER_SESSION_KEYRING: int
KEY_REQKEY_DEFL_GROUP_KEYRING: int
KEYCTL_GET_KEYRING_ID: int
KEYCTL_JOIN_SESSION_KEYRING: int
KEYCTL_UPDATE: int
KEYCTL_REVOKE: int
KEYCTL_CHOWN: int
KEYCTL_SETPERM: int
KEYCTL_DESCRIBE: int
KEYCTL_CLEAR: int
KEYCTL_LINK: int
KEYCTL_UNLINK: int
KEYCTL_SEARCH: int
KEYCTL_READ: int
KEYCTL_INSTANTIATE: int
KEYCTL_NEGATE: int
KEYCTL_SET_REQKEY_KEYRING: int
KEYCTL_SET_TIMEOUT: int
KEYCTL_ASSUME_AUTHORITY: int
KEYCTL_GET_SECURITY: int
KEYCTL_SESSION_TO_PARENT: int
KEYCTL_REJECT: int
KEYCTL_INSTANTIATE_IOV: int
KEYCTL_INVALIDATE: int
KEYCTL_GET_PERSISTENT: int
KEYCTL_DH_COMPUTE: int
KEYCTL_MOVE: int
KEYCTL_CAPABILITIES: int
KEYCTL_PKEY_QUERY: int
KEYCTL_PKEY_ENCRYPT: int
KEYCTL_PKEY_DECRYPT: int
KEYCTL_PKEY_SIGN: int
KEYCTL_PKEY_VERIFY: int
KEYCTL_WATCH_KEY: int
KEY_POS_VIEW: int
KEY_POS_READ: int
KEY_POS_WRITE: int
KEY_POS_SEARCH: int
KEY_POS_LINK: int
KEY_POS_SETATTR: int
KEY_POS_ALL : int
KEY_USR_VIEW: int
KEY_USR_READ: int
KEY_USR_WRITE: int
KEY_USR_SEARCH: int
KEY_USR_LINK: int
KEY_USR_SETATTR: int
KEY_USR_ALL: int
KEY_GRP_VIEW: int
KEY_GRP_READ: int
KEY_GRP_WRITE: int
KEY_GRP_SEARCH: int
KEY_GRP_LINK: int
KEY_GRP_SETATTR: int
KEY_GRP_ALL: int
KEY_OTH_VIEW: int
KEY_OTH_READ: int
KEY_OTH_WRITE: int
KEY_OTH_SEARCH: int
KEY_OTH_LINK: int
KEY_OTH_SETATTR: int
KEY_OTH_ALL: int
