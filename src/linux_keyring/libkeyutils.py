"""keyutils: Python module for interfacing with Linux Kernel keyrings

This module is a wrapper around the libkeyutils library maintained at:
    https://git.kernel.org/pub/scm/linux/kernel/git/dhowells/keyutils.git

This module is used to control the key management system built into the Linux
"""

# Disable the too-many-lines warning. This is almost entirely due to
# docstrings.
# pylint: disable=too-many-lines

from __future__ import annotations
from typing import Dict, TypeVar, Optional
import sys

from . import _libkeyutils as api  # pylint: disable=no-name-in-module

if sys.version_info >= (3, 10):
    from typing import TypeAlias
else:
    from typing_extensions import TypeAlias

KeyPayload = TypeVar('KeyPayload', str, bytes)

key_perm_t: TypeAlias = int
key_serial_t: TypeAlias = int
uid_t: TypeAlias = int
gid_t: TypeAlias = int
unsigned: TypeAlias = int

# per-set bits: v(view) r(read) w(write) x(search) l(link) a(setattr)
_PERM_FLAGS: Dict[str,  int] = {"v": 0x01, "r": 0x02, "w": 0x04, "x": 0x08, "l": 0x10, "a": 0x20}
_SET_SHIFT: Dict[str,  int] = {"p": 24, "u": 16, "g": 8, "o": 0}

KEY_SPEC_THREAD_KEYRING = api.KEY_SPEC_THREAD_KEYRING
KEY_SPEC_PROCESS_KEYRING = api.KEY_SPEC_PROCESS_KEYRING
KEY_SPEC_SESSION_KEYRING = api.KEY_SPEC_SESSION_KEYRING
KEY_SPEC_USER_KEYRING = api.KEY_SPEC_USER_KEYRING
KEY_SPEC_USER_SESSION_KEYRING = api.KEY_SPEC_USER_SESSION_KEYRING
KEY_SPEC_GROUP_KEYRING = api.KEY_SPEC_GROUP_KEYRING
KEY_SPEC_REQKEY_AUTH_KEY = api.KEY_SPEC_REQKEY_AUTH_KEY


def _build_perm_mask(clauses: list[str]) -> int:  # pylint: disable=too-many-branches
    """Build 32-bit key permission mask from chmod-like clauses.
    who: p,u,g,o; ops: +,-,= ; perms: v,r,w,x,l,a or 'all'
    """
    mask = 0
    for c in clauses:
        c = c.strip()
        if not c:
            continue
        i = 0
        who = []
        while i < len(c) and c[i] in "pugo":
            who.append(c[i])
            i += 1
        if not who:
            who = list("pugo")
        if i >= len(c) or c[i] not in "+-=":
            raise ValueError(f"Invalid clause '{c}'")
        op = c[i]
        i += 1
        spec = c[i:]
        if not spec:
            bits = 0
        elif spec == "all":
            bits = 0
            for b in _PERM_FLAGS.values():
                bits |= b
        else:
            bits = 0
            for ch in spec:
                if ch not in _PERM_FLAGS:
                    raise ValueError(f"Unknown perm '{ch}' in '{c}'")
                bits |= _PERM_FLAGS[ch]
        for w in who:
            shift = _SET_SHIFT[w]
            cur = (mask >> shift) & 0x3F
            if op == "=":
                newb = bits
            elif op == "+":
                newb = cur | bits
            elif op == "-":
                newb = cur & (~bits & 0x3F)
            else:
                raise ValueError(f"Unknown op '{op}' in '{c}'")
            mask &= ~(0x3F << shift)
            mask |= (newb & 0x3F) << shift
    return mask


def keyctl_setperm_symbolic(key: key_serial_t, spec: str) -> None:
    """
    Apply permission changes to *key* using chmod-like clauses.

    Parameters
    ----------
    key : key_serial_t
        Key serial number
    spec : str
        String describing permission changes, using the following format:
        **who**: ``p`` (possessor), ``u`` (user), ``g`` (group), ``o`` (other)
        **ops**: ``+``, ``-``, ``=``
        **perms**: ``v`` (view), ``r`` (read), ``w`` (write), ``x`` (search),
        ``l`` (link), ``a`` (setattr) or ``all``


    Raises
    ------
    OSError
        On invalid key or permission errors
    ValueError
        On invalid spec string

    Notes
    -----
    Spec string uses the fallowing format:

    Examples
    --------
    >>> setperm_symbolic(k, "u=rv,go-r")
    >>> setperm_symbolic(k, "p+all,g-x")
    """
    mask = _build_perm_mask(spec.split(","))
    keyctl_setperm(key, mask)


def _encode_optional(value: Optional[KeyPayload]) -> Optional[bytes]:
    if isinstance(value, bytes):
        return value

    if value is None:
        return None

    if isinstance(value, str):
        return value.encode()

    raise TypeError(f"expected bytes or str, not {type(value)}")


def add_key(key_type: str, description: str, payload: Optional[KeyPayload],
            keyring: key_serial_t) -> key_serial_t:
    """
    Create a key of *key_type*/*description* with *payload* and link it into *keyring*.

    Parameters
    ----------
    key_type : str
        Key key_type name (e.g., "user", "asymmetric").
    description : str
        Key description (name).
    payload : bytes | str | None
        Initial payload for the key (format depends on key key_type).
    keyring : int
        Destination keyring ID (may be a KEY_SPEC_* constant).

    Returns
    -------
    int
        Serial number of the created (or updated) key.

    Raises
    ------
    OSError
        On failure (e.g., EPERM/EACCES, ENOMEM, EDQUOT, EEXIST, EINVAL).

    Notes
    -----
    Requires appropriate permissions on *keyring* and may update an existing
    key of the same key_type/description depending on key key_type policy.

    Some key key_types require a valid description and/or payload and others do not.
    OSError(EINVAL) will be raised for key key_types when those values are required but
    not provided.

    See also
    --------
    add_key(2), keyrings(7)
    """
    return api.add_key(key_type.encode(), description.encode(),
                       _encode_optional(payload), keyring)


def request_key(key_type: str, description: str,
                callout_info: Optional[str] = None,
                dest_keyring: key_serial_t = 0) -> key_serial_t:
    """
    Look up a key of *key_type*/*description*; if absent, construct it and link to *dest_keyring*.

    Parameters
    ----------
    key_type, description : str
        Target key key_type and description.
    callout_info : str | None
        Optional data passed to request-key(8) during on-demand instantiation.
    dest_keyring : int
        Keyring to link the found/instantiated key into (KEY_SPEC_* allowed).

    Returns
    -------
    int
        Serial number of the found or newly instantiated key.

    Raises
    ------
    OSError
        On lookup/instantiation errors.

    Notes
    -----
    May trigger the request-key upcall pipeline; handler authority/LSM policy applies.

    See also
    --------
    request_key(2), keyrings(7)
    """
    return api.request_key(key_type.encode(), description.encode(),
                           _encode_optional(callout_info), dest_keyring)


def keyctl_read(key: key_serial_t) -> bytes:
    """
    Read a key's payload and return it.

    Parameters
    ----------
    key : int
        Key serial number.

    Returns
    -------
    bytes
        Payload bytes.

    Raises
    ------
    OSError
        If key type doesn't support read or on permission/size errors.

    See also
    --------
    keyctl_read(3)
    """
    return api.keyctl_read(key)


def keyctl_describe(key: key_serial_t) -> str:
    """
    Return a textual description of *key* (type, uid/gid, perms, etc.).

    Parameters
    ----------
    key : int

    Returns
    -------
    str
        Description as str.

    Raises
    ------
    OSError
        On errors or if view permission is denied.

    See also
    --------
    keyctl_describe(3)
    """
    return api.keyctl_describe(key)


def keyctl_get_security(key: key_serial_t) -> str:
    """
    Fetch the LSM security context (label) for *key* as a string.

    Parameters
    ----------
    key : int

    Returns
    -------
    str
        Security label (format depends on active LSM, e.g., SELinux).

    Raises
    ------
    OSError
        On errors or if view permission is denied.

    See also
    --------
    keyctl_get_security(3)
    """
    return api.keyctl_get_security(key)


def keyctl_capabilities() -> bytes:
    """
    Return a binary capabilities bitmap describing keyctl features supported by the kernel.

    Returns
    -------
    bytes
        Capabilities blob; parse per keyctl_capabilities(3)
        (e.g., RESTRICT_KEYRING, MOVE, PUBLIC_KEY).

    Raises
    ------
    OSError
        On failure.

    See also
    --------
    keyctl_capabilities(3)
    """
    return api.keyctl_capabilities()


def keyctl_update(key: key_serial_t, payload: Optional[KeyPayload] = None) -> None:
    """
    Replace a key's payload (if the key type permits).

    Parameters
    ----------
    key : int
    payload : bytes

    Raises
    ------
    OSError
        On permission/type/format errors.

    See also
    --------
    keyctl_update(3)
    """
    _ = api.keyctl_update(key, _encode_optional(payload))


def keyctl_revoke(key: key_serial_t) -> None:
    """
    Mark *key* as revoked; subsequent use yields EKEYREVOKED.

    Raises
    ------
    OSError
        On failure (e.g., lacking write/setattr permission).

    See also
    --------
    keyctl_revoke(3)
    """
    _ = api.keyctl_revoke(key)


def keyctl_clear(keyring: key_serial_t) -> None:
    """
    Remove all links from *keyring*.

    Raises
    ------
    OSError
        If lacking write permission or on other errors.

    See also
    --------
    keyctl_clear(3)
    """
    _ = api.keyctl_clear(keyring)


def keyctl_unlink(key: key_serial_t, keyring: key_serial_t) -> None:
    """
    Unlink *key* from *keyring* (no-op if not linked).

    Raises
    ------
    OSError
        On errors (e.g., ENOENT when not linked, or lacking write perm).

    See also
    --------
    keyctl_unlink(3)
    """
    _ = api.keyctl_unlink(key, keyring)


def keyctl_link(key: key_serial_t, keyring: key_serial_t) -> None:
    """
    Link *key* into *keyring*, displacing any existing same-type/description link.

    Raises
    ------
    OSError
        On permission/quotas/type errors.

    See also
    --------
    keyctl_link(3)
    """
    _ = api.keyctl_link(key, keyring)


def keyctl_invalidate(key: key_serial_t) -> None:
    """
    Mark *key* invalid; it becomes unfindable and will be garbage collected.

    Raises
    ------
    OSError
        If lacking search permission or on other errors.

    See also
    --------
    keyctl_invalidate(3)
    """
    _ = api.keyctl_invalidate(key)


def keyctl_chown(key: key_serial_t, uid: uid_t, gid: gid_t) -> None:
    """
    Change *key*’s owner/group (use -1 to leave a field unchanged).

    Raises
    ------
    OSError
        If caller lacks CAP_SYS_ADMIN or tries to set disallowed IDs.

    See also
    --------
    keyctl_chown(3)
    """
    _ = api.keyctl_chown(key, uid, gid)


def keyctl_setperm(key: key_serial_t, perm: key_perm_t) -> None:
    """
    Set *key*’s permission mask (VIEW/READ/WRITE/SEARCH/LINK/SETATTR bitfields).

    Parameters
    ----------
    perm : int
        Bitwise OR of KEY_* permission bits for POS/USR/GRP/OTH categories.

    Raises
    ------
    OSError
        On invalid bits or lacking setattr permission.

    See also
    --------
    keyctl_setperm(3), KEYCTL_SETPERM(2const)
    """
    _ = api.keyctl_setperm(key, perm)


def keyctl_set_timeout(key: key_serial_t, timeout: int) -> None:
    """
    Set *key*’s expiration timer to *timeout* seconds (0 cancels expiry).

    Raises
    ------
    OSError
        On errors; expired keys yield EKEYEXPIRED on later access.

    See also
    --------
    keyctl_set_timeout(3)
    """
    _ = api.keyctl_set_timeout(key, timeout)


def keyctl_assume_authority(key: key_serial_t) -> key_serial_t:
    """
    Assume authority for an uninstantiated key during request-key handling.

    Parameters
    ----------
    key : key_serial_t
        Authorization key (e.g., KEY_SPEC_REQKEY_AUTH_KEY) or 0 to drop authority.

    Returns
    -------
    key_serial_t
        Previous assumed key ID on success.

    Raises
    ------
    OSError
        If authorization key is missing/revoked.

    See also
    --------
    keyctl_assume_authority(3), KEYCTL_ASSUME_AUTHORITY(2const), request_key(2)
    """
    return key_serial_t(api.keyctl_assume_authority(key))


def keyctl_join_session_keyring(name: Optional[str]) -> key_serial_t:
    """
    Join (or create) a session keyring.

    Parameters
    ----------
    name : str |  None
        Named session keyring to join; None creates a new anonymous session keyring.

    Returns
    -------
    int
        The session keyring ID subscribed by the calling process.

    Raises
    ------
    OSError
        On permission or LSM policy failure.

    See also
    --------
    keyctl_join_session_keyring(3), session-keyring(7)
    """
    return key_serial_t(api.keyctl_join_session_keyring(_encode_optional(name)))


def keyctl_search(keyring: key_serial_t, key_type: str, description: str,
                  dest_keyring: key_serial_t = 0) -> key_serial_t:
    """
    Breadth-first search *keyring* tree for *key_type*/*description*, optionally linking result.

    Parameters
    ----------
    keyring : key_serial_t
        Root of the search (KEY_SPEC_* allowed).
    key_type, description : str
    dest_keyring : key_serial_t
        If nonzero, link found key into this keyring (replacing any same-type/description link).

    Returns
    -------
    key_serial_t
        Serial number of the found key.

    Raises
    ------
    OSError
        On not found/permission errors.

    See also
    --------
    keyctl_search(3)
    """
    return api.keyctl_search(keyring, key_type.encode(), description.encode(),
                             dest_keyring)


def keyctl_restrict_keyring(keyring: key_serial_t,
                            key_type: Optional[str] = None,
                            restriction: Optional[str] = None) -> None:
    """
    Restrict which keys may be linked into *keyring*.

    Parameters
    ----------
    keyring : key_serial_t
    key_type : str | None
        Key type to restrict to, or None.
    restriction : str |  None
        Restriction scheme string for that type (format is type-specific); if both
        *type* and *restriction* are None, all future links will be rejected.

    Raises
    ------
    OSError
        If restriction not supported or insufficient permission.

    See also
    --------
    keyctl_restrict_keyring(3)
    """
    _ = api.keyctl_restrict_keyring(keyring, _encode_optional(key_type),
                                    _encode_optional(restriction))


def keyctl_get_keyring_ID(key: key_serial_t, create: int) -> key_serial_t:
    """
    Resolve a special key/keyring ID to a real serial; optionally create if absent.

    Parameters
    ----------
    key : int
        A real or special KEY_SPEC_* ID.
    create : int
        Nonzero to create if it doesn't exist (where appropriate).

    Returns
    -------
    int
        Real keyring serial number.

    Raises
    ------
    OSError
        On failure.

    See also
    --------
    keyctl_get_keyring_ID(3)
    """
    return api.keyctl_get_keyring_ID(key, create)


def keyctl_session_to_parent() -> None:
    """
    Replace the parent process's session keyring with the caller's session keyring.

    Raises
    ------
    OSError
        If credentials/LSM checks fail; cannot affect init or kernel threads.

    See also
    --------
    keyctl_session_to_parent(3), session-keyring(7)
    """
    _ = api.keyctl_session_to_parent()


def keyctl_set_reqkey_keyring(which: int) -> int:
    """
    Set default destination keyring for implicit key requests for this thread.

    Parameters
    ----------
    which : int
        One of KEY_REQKEY_DEFL_* constants (e.g., DEFAULT, THREAD_KEYRING, PROCESS_KEYRING,
        SESSION_KEYRING, USER_KEYRING, USER_SESSION_KEYRING).

    Returns
    -------
    int
        Previous default setting.

    Raises
    ------
    OSError
        On invalid setting.

    See also
    --------
    keyctl_set_reqkey_keyring(3)
    """
    return api.keyctl_set_reqkey_keyring(which)


def keyctl_get_persistent(uid: uid_t, keyring: key_serial_t) -> int:
    """
    Get the persistent keyring for *uid*, optionally linking it to *keyring*.

    Parameters
    ----------
    uid : int
        User ID (requires privilege to access others’ keyrings).
    keyring : int
        Destination keyring to link (or 0 for none).

    Returns
    -------
    int
        Persistent keyring serial.

    Raises
    ------
    OSError
        On permission/namespace errors.

    See also
    --------
    keyctl_get_persistent(3), keyrings(7)
    """
    return key_serial_t(api.keyctl_get_persistent(uid, keyring))


def keyctl_move(key: key_serial_t, from_keyring: key_serial_t, to_keyring: key_serial_t,
                flags: int = 0) -> None:
    """
    Atomically move *key* from *from_keyring* to *to_keyring*.

    Parameters
    ----------
    flags : int
        Bitwise OR of flags (e.g., KEYCTL_MOVE_EXCL to refuse displacement).

    Raises
    ------
    OSError
        On permission errors or conflicting links.

    See also
    --------
    keyctl_move(3)
    """
    _ = api.keyctl_move(key, from_keyring, to_keyring, flags)


def keyctl_instantiate(key: key_serial_t, payload: Optional[KeyPayload] = None,
                       keyring: key_serial_t = 0) -> None:
    """
    Instantiate an uninstantiated key with *payload*, optionally linking into *keyring*.

    Parameters
    ----------
    key : int
        Serial number of key to instantiate
    payload : bytes | str | None
        Payload for the key
    keyring : int
        Serial number of keyring to link, 0 if none

    Notes
    -----
    Usable from a request-key(8) handler with valid authorization.

    Raises
    ------
    OSError
        If authorization missing or payload invalid for key type.

    See also
    --------
    keyctl_instantiate(3), request_key(2)
    """
    _ = api.keyctl_instantiate(key, _encode_optional(payload), keyring)


def keyctl_instantiate_iov(key: key_serial_t,
                           iov: Optional[list[KeyPayload]] = None,
                           keyring: key_serial_t = 0) -> None:
    """
    Instantiate an uninstantiated key from a vector of payload buffers,
    optionally linking into *keyring*.

    Parameters
    ----------
    key : int
        Serial number of key to instantiate
    iov : list[str | bytes]
        Sequence of payload fragments (equivalent to struct iovec array).
    keyring : int
        Serial number of keyring to link, 0 if none

    Raises
    ------
    OSError
        On authorization/type errors.

    See also
    --------
    keyctl_instantiate_iov(3)
    """

    iov_bytes: Optional[list[bytes]] = None
    if iov:
        iov_bytes = []
        if len(iov):
            if isinstance(iov[0], str):
                expected = str
            else:
                expected = bytes
                iov_bytes = iov

        for payload in iov:
            if not isinstance(payload, expected):
                raise ValueError("iov must be list of one type: str or bytes")

            if isinstance(payload, str):
                iov_bytes.append(payload.encode())

    _ = api.keyctl_instantiate_iov(key, iov_bytes, keyring)


def keyctl_negate(key: key_serial_t, timeout: unsigned, keyring: key_serial_t) -> None:
    """
    Negatively instantiate *key* with lifetime *timeout* seconds and optional link.

    Raises
    ------
    OSError
        On authorization errors.

    See also
    --------
    keyctl_negate(3), keyctl_reject(3)
    """
    if timeout < 0:
        raise ValueError("timeout must be >= 0")
    _ = api.keyctl_negate(key, timeout, keyring)


def keyctl_reject(key: key_serial_t, timeout: unsigned, error: int, keyring: key_serial_t) -> None:
    """
    Negatively instantiate *key*, specifying *timeout* and the error to return when matched.

    Parameters
    ----------
    error : int
        Errno to report on future matches (e.g., EKEYREJECTED/EKEYREVOKED/EKEYEXPIRED).

    Raises
    ------
    OSError
        On authorization errors.

    See also
    --------
    keyctl_reject(3)
    """
    if timeout < 0:
        raise ValueError("timeout must be >= 0")
    _ = api.keyctl_reject(key, timeout, error, keyring)


def keyctl_dh_compute(priv: key_serial_t, prime: key_serial_t, base: key_serial_t) -> bytes:
    """
    Compute a Diffie–Hellman public/shared value using keys in the kernel keyring.

    Parameters
    ----------
    priv, prime, base : int
        Serial numbers of "user" keys holding the private exponent, prime (p),
        and base (g or peer pub).

    Returns
    -------
    bytes
        Raw DH result (possibly truncated if *buflen* was too small).

    Raises
    ------
    OSError
        On permission/type errors.

    See also
    --------
    keyctl_dh_compute(3), KEYCTL_DH_COMPUTE(2const)
    """
    return api.keyctl_dh_compute_alloc(priv, prime, base)


def keyctl_dh_compute_kdf(priv: key_serial_t, prime: key_serial_t, base: key_serial_t,
                          hashname: str, otherinfo: Optional[bytes] = None,
                          outlen: key_serial_t = 0) -> bytes:
    # pylint: disable=too-many-positional-arguments disable=too-many-arguments
    """
    Compute DH and apply a key-derivation function (KDF) with *hashname* and *otherinfo*.

    Parameters
    ----------
    priv : key_serial_t
        Serial number of key containing private key
    prime : key_serial_t
        Serial number of key containing prime
    base : key_serial_t
        Serial number of key containing base
    hashname : str
        Hash/KDF name (e.g., "sha256").
    otherinfo : bytes
        Additional KDF context (passed to the kernel).
    outlen : int
        Desired output length. If 0, the buffer size will be queried prior to allocation.

    Returns
    -------
    bytes
        Derived key bytes

    Raises
    ------
    OSError
        On unsupported KDF or parameter errors.

    See also
    --------
    keyctl_dh_compute_kdf(3), KEYCTL_DH_COMPUTE(2const)
    """
    return api.keyctl_dh_compute_kdf(priv, prime, base, hashname.encode(),
                                     otherinfo, outlen)


def keyctl_pkey_query(key: key_serial_t, info: str) -> Dict[str, int]:
    """
    Query public-key parameters/limits for *key* (typically type 'asymmetric').

    Parameters
    ----------
    key : key_serial_t
        Serial number of key to use
    info : str
        Space/tab-separated "key[=value]" options string (algorithm, encoding, etc.).

    Returns
    -------
    tuple
        Parsed capability/size information (see man page for fields).

    Raises
    ------
    OSError
        On permission or unsupported operation.

    See also
    --------
    keyctl_pkey_query(3), asymmetric-key(7)
    """

    qresult = api.keyctl_pkey_query(key, info.encode())

    return {
        "supported_ops": qresult[0],
        "key_size":      qresult[1],
        "max_data_size": qresult[2],
        "max_sig_size":  qresult[3],
        "max_enc_size":  qresult[4],
        "max_dec_size":  qresult[5],
    }


def keyctl_pkey_encrypt(key: key_serial_t, info: str, data: bytes,
                        outlen: int = 0) -> bytes:
    """
    Encrypt *data* using crypto material attached to *key*.

    Parameters
    ----------
    key : key_serial_t
        Serial number of public key to use
    info : str
        Options (algorithm/encoding/padding); use :func:`keyctl_pkey_query` to size buffers.
    data : bytes
        Data to Encrypt
    outlen : int
        Size of output buffer.  If 0, output buffer size will be queried before encryption.

    Returns
    -------
    bytes
        Encrypted blob.

    Raises
    ------
    OSError
        On permission/size/algorithm errors.

    See also
    --------
    keyctl_pkey_encrypt(3)
    """
    if outlen == 0:
        q = keyctl_pkey_query(key, info)
        outlen = q['max_enc_size']
    return api.keyctl_pkey_encrypt(key, info.encode(), data, outlen)


def keyctl_pkey_decrypt(key: key_serial_t, info: str, enc: bytes,
                        outlen: int = 0) -> bytes:
    """
    Decrypt *enc* using crypto material attached to *key*.

    Parameters
    ----------
    key : key_serial_t
        Serial number of private key to use
    info : str
        Options string; use :func:`keyctl_pkey_query` to determine sizes.
    enc : bytes
        Encrypted data to decrypt
    outlen : int
        Size of output buffer.  If 0, output buffer size will be queried before decryption.

    Returns
    -------
    bytes
        Decrypted data.

    Raises
    ------
    OSError
        On permission/size/algorithm errors.

    See also
    --------
    keyctl_pkey_decrypt(3)
    """
    if outlen == 0:
        q = keyctl_pkey_query(key, info)
        outlen = q['max_dec_size']
    return api.keyctl_pkey_decrypt(key, info.encode(), enc, outlen)


def keyctl_pkey_sign(key: key_serial_t, info: str, data: bytes,
                     siglen: int = 0) -> bytes:
    """
    Produce a detached signature over *data* using *key*.

    Parameters
    ----------
    key : key_serial_t
        Serial number of private key to use
    info : str
        Options (algorithm/encoding); consult :func:`keyctl_pkey_query`.
    siglen : int
        Size of output signature buffer.  If 0, output buffer size will be queried before signing.

    Returns
    -------
    bytes
        Signature.

    Raises
    ------
    OSError
        On permission/size/algorithm errors.

    See also
    --------
    keyctl_pkey_sign(3)
    """
    if siglen == 0:
        q = keyctl_pkey_query(key, info)
        siglen = q['max_sig_size']
    return api.keyctl_pkey_sign(key, info.encode(), data, siglen)


def keyctl_pkey_verify(key: key_serial_t, info: str, data: bytes, sig: bytes) -> None:
    """
    Verify a detached *sig* over *data* using *key*.

    Raises
    ------
    OSError
        If verification fails or operation unsupported.

    See also
    --------
    keyctl_pkey_verify(3)
    """
    _ = api.keyctl_pkey_verify(key, info.encode(), data, sig)


def keyctl_watch_key(key: key_serial_t, watch_queue_fd: int, watch_id: int) -> None:
    """
    Add/remove a watch for changes to *key* and send notifications to *watch_queue_fd*.

    Parameters
    ----------
    watch_queue_fd : int
        FD of a watch_queue-enabled pipe.
    watch_id : int
        0..255 to add a watch with this ID; -1 to remove.

    Raises
    ------
    OSError
        On invalid FD/ID or permission errors.

    See also
    --------
    keyctl_watch_key(3), watch_queue(7)
    """
    _ = api.keyctl_watch_key(key, watch_queue_fd, watch_id)


def keyctl_read_as_str(key: int, encoding: str = 'utf-8') -> str:
    """
    Read a key's payload and return it as a string.

    Parameters
    ----------
    key : int
        Key serial number.

    Returns
    -------
    str
        Payload bytes as a string.

    Raises
    ------
    OSError
        If key type doesn't support read or on permission/size errors.

    See also
    --------
    keyctl_read_alloc(3)
    """
    return keyctl_read(key).decode(encoding)
