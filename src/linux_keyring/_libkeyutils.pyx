# cython: language_level=3
from cpython.bytes cimport PyBytes_FromStringAndSize
from libc.stdlib cimport malloc, free
from cpython.mem cimport PyMem_Malloc, PyMem_Free
from . cimport _libkeyutils_api as c
from . cimport _libkeyutils_types as t
from libc.errno cimport errno as c_errno
import errno
import os

def add_key(bytes type, bytes description, bytes payload, int keyring) -> int:
    cdef char *payload_p
    cdef int payload_len
    if payload is None:
        payload_p = NULL
        payload_len = 0
    else:
        payload_p = payload
        payload_len = len(payload)

    cdef c.key_serial_t ret = c.add_key(<const char*>type,
                                        <const char*>description,
                                        <const void*>payload_p,
                                        payload_len, keyring)
    if ret == -1:
        raise OSError(c_errno, os.strerror(c_errno))
    return <int>ret

def request_key(bytes type, bytes description, bytes callout_info,
                int dest_keyring) -> int:
    cdef c.key_serial_t ret = c.request_key(<const char*>type,
                                            <const char*>description,
                                            <const char*>callout_info if callout_info is not None else NULL,
                                            dest_keyring)
    if ret == -1:
        raise OSError(c_errno, os.strerror(c_errno))
    return <int>ret

def keyctl_read(int key) -> bytes:
    cdef void* buf = NULL
    cdef long n = c.keyctl_read_alloc(key, &buf)
    if n == -1:
        raise OSError(c_errno, os.strerror(c_errno))
    try:
        return b"" if n == 0 else PyBytes_FromStringAndSize(<char*>buf, n)
    finally:
        if buf != NULL: free(buf)

def keyctl_describe(int key) -> str:
    cdef char* buf = NULL
    cdef long n = c.keyctl_describe_alloc(key, &buf)
    if n == -1:
        raise OSError(c_errno, os.strerror(c_errno))
    try:
        return "" if n == 0 else PyBytes_FromStringAndSize(buf, n).decode('utf-8')
    finally:
        if buf != NULL: free(buf)

def keyctl_get_security(int key) -> str:
    cdef char* buf = NULL
    cdef long n = c.keyctl_get_security_alloc(key, &buf)
    if n == -1:
        raise OSError(c_errno, os.strerror(c_errno))
    try:
        return "" if n == 0 else PyBytes_FromStringAndSize(buf, n).decode('utf-8')
    finally:
        if buf != NULL: free(buf)

def keyctl_capabilities() -> bytes:
    cdef unsigned char buf[2]
    cdef long n = c.keyctl_capabilities(buf, sizeof(buf))
    if n == -1:
        raise OSError(c_errno, os.strerror(c_errno))
    return b"" if n == 0 else PyBytes_FromStringAndSize(<char*>buf, n)

def keyctl_update(int key, bytes payload) -> int:
    cdef char *payload_p
    cdef int payload_len
    if payload is None:
        payload_p = NULL
        payload_len = 0
    else:
        payload_p = payload
        payload_len = len(payload)

    cdef long ret = c.keyctl_update(key, <const void*>payload_p, payload_len)
    if ret == -1:
        raise OSError(c_errno, os.strerror(c_errno))
    return <int>ret

def keyctl_revoke(int key) -> int:
    cdef long ret = c.keyctl_revoke(key)
    if ret == -1:
        raise OSError(c_errno, os.strerror(c_errno))
    return <int>ret

def keyctl_clear(int keyring) -> int:
    cdef long ret = c.keyctl_clear(keyring)
    if ret == -1:
        raise OSError(c_errno, os.strerror(c_errno))
    return <int>ret

def keyctl_unlink(int key, int keyring) -> int:
    cdef long ret = c.keyctl_unlink(key, keyring)
    if ret == -1:
        raise OSError(c_errno, os.strerror(c_errno))
    return <int>ret

def keyctl_link(int key, int keyring) -> int:
    cdef long ret = c.keyctl_link(key, keyring)
    if ret == -1:
        raise OSError(c_errno, os.strerror(c_errno))
    return <int>ret

def keyctl_invalidate(int key) -> int:
    cdef long ret = c.keyctl_invalidate(key)
    if ret == -1:
        raise OSError(c_errno, os.strerror(c_errno))
    return <int>ret

def keyctl_chown(int key, int uid, int gid) -> int:
    cdef long ret = c.keyctl_chown(key, uid, gid)
    if ret == -1:
        raise OSError(c_errno, os.strerror(c_errno))
    return <int>ret

def keyctl_setperm(int key, unsigned int perm) -> int:
    cdef long ret = c.keyctl_setperm(key, perm)
    if ret == -1:
        raise OSError(c_errno, os.strerror(c_errno))
    return <int>ret

def keyctl_set_timeout(int key, unsigned int timeout) -> int:
    cdef long ret = c.keyctl_set_timeout(key, timeout)
    if ret == -1:
        raise OSError(c_errno, os.strerror(c_errno))
    return <int>ret

def keyctl_assume_authority(int key) -> int:
    cdef long ret = c.keyctl_assume_authority(key)
    if ret == -1:
        raise OSError(c_errno, os.strerror(c_errno))
    return <int>ret

def keyctl_join_session_keyring(name: bytes|None) -> int:
    cdef const char* nm = <const char*>name if name is not None else NULL
    cdef long ret = c.keyctl_join_session_keyring(nm)
    if ret == -1:
        raise OSError(c_errno, os.strerror(c_errno))
    return <int>ret

def keyctl_search(int keyring, bytes type, bytes description, int dest_keyring) -> int:
    cdef long ret = c.keyctl_search(keyring, <const char*>type, <const char*>description, dest_keyring)
    if ret == -1:
        raise OSError(c_errno, os.strerror(c_errno))
    return <int>ret

def keyctl_restrict_keyring(int keyring, bytes type_or_null, bytes restriction_or_null) -> int:
    cdef const char* t = <const char*>type_or_null if type_or_null is not None else NULL
    cdef const char* r = <const char*>restriction_or_null if restriction_or_null is not None else NULL
    cdef long ret = c.keyctl_restrict_keyring(keyring, t, r)
    if ret == -1:
        raise OSError(c_errno, os.strerror(c_errno))
    return <int>ret

def keyctl_get_keyring_ID(int key, int create) -> int:
    cdef long ret = c.keyctl_get_keyring_ID(key, create)
    if ret == -1:
        raise OSError(c_errno, os.strerror(c_errno))
    return <int>ret

def keyctl_session_to_parent() -> int:
    cdef long ret = c.keyctl_session_to_parent()
    if ret == -1:
        raise OSError(c_errno, os.strerror(c_errno))
    return <int>ret

def keyctl_set_reqkey_keyring(int which) -> int:
    cdef long ret = c.keyctl_set_reqkey_keyring(which)
    if ret == -1:
        raise OSError(c_errno, os.strerror(c_errno))
    return <int>ret

def keyctl_get_persistent(int uid, int keyring) -> int:
    cdef long ret = c.keyctl_get_persistent(uid, keyring)
    if ret == -1:
        raise OSError(c_errno, os.strerror(c_errno))
    return <int>ret

def keyctl_move(int key, int from_keyring, int to_keyring, unsigned int flags=0) -> int:
    cdef long ret = c.keyctl_move(key, from_keyring, to_keyring, flags)
    if ret == -1:
        raise OSError(c_errno, os.strerror(c_errno))
    return <int>ret

def keyctl_instantiate(int key, bytes payload, int keyring) -> int:
    cdef char *payload_p
    cdef int payload_len
    if payload is None:
        payload_p = NULL
        payload_len = 0
    else:
        payload_p = payload
        payload_len = len(payload)

    cdef long ret = c.keyctl_instantiate(key, <const void*>payload_p,
                                         payload_len, keyring)
    if ret == -1:
        raise OSError(c_errno, os.strerror(c_errno))
    return <int>ret

def keyctl_instantiate_iov(int key, list iov_py, int keyring) -> int:
    cdef t.iovec*iov
    cdef int n
    try:
        if iov_py is None:
            iov = NULL
            n = 0
        else:
            n = len(iov_py)
            iov = <t.iovec*> PyMem_Malloc(n * sizeof(t.iovec))
            if iov == NULL:
                raise OSError(c_errno, os.strerror(c_errno))
        for i in range(n):
            buf = <bytes> iov_py[i]
            iov[i].iov_base = <void*> buf
            iov[i].iov_len  = len(buf)

        ret = c.keyctl_instantiate_iov(key, iov, n, keyring)
        if ret == -1:
            raise OSError(c_errno, os.strerror(c_errno))

        return <int>ret
    finally:
        PyMem_Free(iov)

def keyctl_negate(int key, unsigned int timeout, int keyring) -> int:
    cdef long ret = c.keyctl_negate(key, timeout, keyring)
    if ret == -1:
        raise OSError(c_errno, os.strerror(c_errno))
    return <int>ret

def keyctl_reject(int key, unsigned int timeout, unsigned int error, int keyring) -> int:
    cdef long ret = c.keyctl_reject(key, timeout, error, keyring)
    if ret == -1:
        raise OSError(c_errno, os.strerror(c_errno))
    return <int>ret

def keyctl_dh_compute(int priv, int prime, int base, size_t buflen) -> bytes:
    cdef bytes out = PyBytes_FromStringAndSize(NULL, buflen)
    cdef long n = c.keyctl_dh_compute(priv, prime, base, <char*> out, buflen)
    if n == -1:
        raise OSError(c_errno, os.strerror(c_errno))
    return (<bytes>out)[:n]

def keyctl_dh_compute_alloc(int priv, int prime, int base) -> bytes:
    cdef void* buf = NULL
    cdef long n = c.keyctl_dh_compute_alloc(priv, prime, base, &buf)
    if n == -1:
        raise OSError(c_errno, os.strerror(c_errno))
    try:
        return b"" if n == 0 else PyBytes_FromStringAndSize(<char*>buf, n)
    finally:
        if buf != NULL:
            free(buf)

def keyctl_dh_compute_kdf(int priv, int prime, int base,
                          bytes hashname, bytes otherinfo, int outlen) -> bytes:
    cdef long sz
    if outlen == 0:
        sz = c.keyctl_dh_compute_kdf(priv, prime, base,
                                          <const char*>hashname, <const char*>otherinfo, len(otherinfo),
                                          <char *>NULL, 0)
        if sz == -1:
            raise OSError(c_errno, os.strerror(c_errno))
        outlen = int(sz)

    cdef bytes out = PyBytes_FromStringAndSize(NULL, outlen)
    n = c.keyctl_dh_compute_kdf(priv, prime, base,
                                          <const char*>hashname, <const char*>otherinfo, len(otherinfo),
                                          <char*> out, outlen)
    if n == -1:
        raise OSError(c_errno, os.strerror(c_errno))
    return (<bytes>out)[:n]

def keyctl_pkey_query(int key, bytes info) -> tuple:
    cdef t.keyctl_pkey_query q
    cdef long ret = c.keyctl_pkey_query(key, <const char*>info, &q)
    if ret == -1:
        raise OSError(c_errno, os.strerror(c_errno))
    return (q.supported_ops, q.key_size, q.max_data_size, q.max_sig_size, q.max_enc_size, q.max_dec_size)

def keyctl_pkey_encrypt(int key, bytes info, bytes data, int outlen) -> bytes:
    cdef bytes out = PyBytes_FromStringAndSize(NULL, outlen)
    cdef long n = c.keyctl_pkey_encrypt(key, <const char*>info, <const void*><const char *>data, len(data),
                                        <void*><char*> out, outlen)
    if n == -1:
        raise OSError(c_errno, os.strerror(c_errno))
    return (<bytes>out)[:n]

def keyctl_pkey_decrypt(int key, bytes info, bytes enc, size_t outlen) -> bytes:
    cdef bytes out = PyBytes_FromStringAndSize(NULL, outlen)
    cdef long n = c.keyctl_pkey_decrypt(key, <const char*>info, <const void*><const char *>enc, len(enc),
                                        <void*> out, outlen)
    if n == -1:
        raise OSError(c_errno, os.strerror(c_errno))
    return (<bytes>out)[:n]

def keyctl_pkey_sign(int key, bytes info, bytes data, size_t siglen) -> bytes:
    cdef bytes out = PyBytes_FromStringAndSize(NULL, siglen)
    cdef long n = c.keyctl_pkey_sign(key, <const char*>info, <const void*><const char *>data, len(data),
                                     <void*> out, siglen)
    if n == -1:
        raise OSError(c_errno, os.strerror(c_errno))
    return (<bytes>out)[:n]

def keyctl_pkey_verify(int key, bytes info, bytes data, bytes sig) -> int:
    cdef long ret = c.keyctl_pkey_verify(key, <const char*>info, <const void*>data, len(data),
                                         <const void*>sig, len(sig))
    if ret == -1:
        raise OSError(c_errno, os.strerror(c_errno))
    return <int>ret

def keyctl_watch_key(int key, int watch_queue_fd, int watch_id) -> int:
    cdef long ret = c.keyctl_watch_key(key, watch_queue_fd, watch_id)
    if ret == -1:
        raise OSError(c_errno, os.strerror(c_errno))
    return <int>ret

def keyctl_raw(int cmd, unsigned long a2=0, unsigned long a3=0, unsigned long a4=0, unsigned long a5=0) -> int:
    cdef long ret = c.keyctl(cmd, a2, a3, a4, a5)
    if ret == -1:
        raise OSError(c_errno, os.strerror(c_errno))
    return <int>ret

KEY_SPEC_THREAD_KEYRING = c.KEY_SPEC_THREAD_KEYRING
KEY_SPEC_PROCESS_KEYRING = c.KEY_SPEC_PROCESS_KEYRING
KEY_SPEC_SESSION_KEYRING = c.KEY_SPEC_SESSION_KEYRING
KEY_SPEC_USER_KEYRING = c.KEY_SPEC_USER_KEYRING
KEY_SPEC_USER_SESSION_KEYRING = c.KEY_SPEC_USER_SESSION_KEYRING
KEY_SPEC_GROUP_KEYRING = c.KEY_SPEC_GROUP_KEYRING
KEY_SPEC_REQKEY_AUTH_KEY = c.KEY_SPEC_REQKEY_AUTH_KEY
#KEY_SPEC_REQUESTOR_KEYRING = c.KEY_SPEC_REQUESTOR_KEYRING

#KEYCTL_GET_KEYRING_ID      = c.KEYCTL_GET_KEYRING_ID
#KEYCTL_JOIN_SESSION_KEYRING= c.KEYCTL_JOIN_SESSION_KEYRING
#KEYCTL_UPDATE              = c.KEYCTL_UPDATE
#KEYCTL_REVOKE              = c.KEYCTL_REVOKE
#KEYCTL_CHOWN               = c.KEYCTL_CHOWN
#KEYCTL_SETPERM             = c.KEYCTL_SETPERM
#KEYCTL_DESCRIBE            = c.KEYCTL_DESCRIBE
#KEYCTL_CLEAR               = c.KEYCTL_CLEAR
#KEYCTL_LINK                = c.KEYCTL_LINK
#KEYCTL_UNLINK              = c.KEYCTL_UNLINK
#KEYCTL_SEARCH              = c.KEYCTL_SEARCH
#KEYCTL_READ                = c.KEYCTL_READ
#KEYCTL_INSTANTIATE         = c.KEYCTL_INSTANTIATE
#KEYCTL_NEGATE              = c.KEYCTL_NEGATE
#KEYCTL_SET_REQKEY_KEYRING  = c.KEYCTL_SET_REQKEY_KEYRING
#KEYCTL_SET_TIMEOUT         = c.KEYCTL_SET_TIMEOUT
#KEYCTL_ASSUME_AUTHORITY    = c.KEYCTL_ASSUME_AUTHORITY
#KEYCTL_GET_SECURITY        = c.KEYCTL_GET_SECURITY
#KEYCTL_SESSION_TO_PARENT   = c.KEYCTL_SESSION_TO_PARENT
#KEYCTL_REJECT              = c.KEYCTL_REJECT
#KEYCTL_INSTANTIATE_IOV     = c.KEYCTL_INSTANTIATE_IOV
#KEYCTL_INVALIDATE          = c.KEYCTL_INVALIDATE
#KEYCTL_GET_PERSISTENT      = c.KEYCTL_GET_PERSISTENT
#KEYCTL_DH_COMPUTE          = c.KEYCTL_DH_COMPUTE
#KEYCTL_MOVE                = c.KEYCTL_MOVE
#KEYCTL_WATCH_KEY           = c.KEYCTL_WATCH_KEY

KEY_POS_VIEW	  = c.KEY_POS_VIEW
KEY_POS_READ	  = c.KEY_POS_READ
KEY_POS_WRITE	  = c.KEY_POS_WRITE
KEY_POS_SEARCH	  = c.KEY_POS_SEARCH
KEY_POS_LINK	  = c.KEY_POS_LINK
KEY_POS_SETATTR	  = c.KEY_POS_SETATTR
KEY_POS_ALL 	  = c.KEY_POS_ALL
KEY_USR_VIEW	  = c.KEY_USR_VIEW
KEY_USR_READ	  = c.KEY_USR_READ
KEY_USR_WRITE	  = c.KEY_USR_WRITE
KEY_USR_SEARCH	  = c.KEY_USR_SEARCH
KEY_USR_LINK	  = c.KEY_USR_LINK
KEY_USR_SETATTR	  = c.KEY_USR_SETATTR
KEY_USR_ALL	      = c.KEY_USR_ALL
KEY_GRP_VIEW	  = c.KEY_GRP_VIEW
KEY_GRP_READ	  = c.KEY_GRP_READ
KEY_GRP_WRITE	  = c.KEY_GRP_WRITE
KEY_GRP_SEARCH	  = c.KEY_GRP_SEARCH
KEY_GRP_LINK	  = c.KEY_GRP_LINK
KEY_GRP_SETATTR	  = c.KEY_GRP_SETATTR
KEY_GRP_ALL	      = c.KEY_GRP_ALL
KEY_OTH_VIEW	  = c.KEY_OTH_VIEW
KEY_OTH_READ	  = c.KEY_OTH_READ
KEY_OTH_WRITE	  = c.KEY_OTH_WRITE
KEY_OTH_SEARCH	  = c.KEY_OTH_SEARCH
KEY_OTH_LINK	  = c.KEY_OTH_LINK
KEY_OTH_SETATTR	  = c.KEY_OTH_SETATTR
KEY_OTH_ALL	      = c.KEY_OTH_ALL

