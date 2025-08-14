# distutils: language = c
from libc.stdint cimport int32_t, uint32_t
from posix.types cimport uid_t, gid_t

from . cimport _libkeyutils_types as t

cdef extern from "<keyutils.h>":
    ctypedef int32_t key_serial_t
    ctypedef uint32_t key_perm_t

    long keyctl(int cmd, ...)

    key_serial_t add_key(const char *type, const char *description,
                         const void *payload, size_t plen,
                         key_serial_t keyring)
    key_serial_t request_key(const char *type, const char *description,
                             const char *callout_info, key_serial_t dest_keyring)

    long keyctl_read_alloc(key_serial_t key, void **_buffer)
    long keyctl_describe_alloc(key_serial_t key, char **_buffer)
    long keyctl_get_security_alloc(key_serial_t key, char **_buffer)
    long keyctl_capabilities(unsigned char *_buffer, size_t buflen)

    long keyctl_read(key_serial_t key, char *buffer, size_t buflen)
    long keyctl_describe(key_serial_t key, char *buffer, size_t buflen)
    long keyctl_get_security(key_serial_t key, char *buffer, size_t buflen)

    long keyctl_revoke(key_serial_t key)
    long keyctl_clear(key_serial_t keyring)
    long keyctl_unlink(key_serial_t key, key_serial_t keyring)
    long keyctl_link(key_serial_t key, key_serial_t keyring)
    long keyctl_invalidate(key_serial_t key)
    long keyctl_chown(key_serial_t key, uid_t uid, gid_t gid)
    long keyctl_setperm(key_serial_t key, key_perm_t perm)
    long keyctl_set_timeout(key_serial_t key, unsigned timeout)
    long keyctl_assume_authority(key_serial_t key)
    long keyctl_join_session_keyring(const char *name)
    long keyctl_search(key_serial_t keyring, const char *type, const char *description, key_serial_t dest_keyring)
    long keyctl_update(key_serial_t key, const void *payload, size_t plen)
    long keyctl_restrict_keyring(key_serial_t keyring, const char *type, const char *restriction)
    long keyctl_get_keyring_ID(key_serial_t key, int create)
    long keyctl_session_to_parent()
    long keyctl_set_reqkey_keyring(int reqkey_defl)
    long keyctl_get_persistent(unsigned int uid, key_serial_t keyring)
    long keyctl_move(key_serial_t key, key_serial_t from_keyring, key_serial_t to_keyring, unsigned int flags)

    long keyctl_instantiate(key_serial_t key, const void *payload, size_t plen, key_serial_t keyring)
    long keyctl_instantiate_iov(key_serial_t key, const t.iovec *iov, unsigned ioc, key_serial_t keyring)
    long keyctl_negate(key_serial_t key, unsigned timeout, key_serial_t keyring)
    long keyctl_reject(key_serial_t key, unsigned timeout, unsigned error, key_serial_t keyring)

    long keyctl_dh_compute(key_serial_t priv, key_serial_t prime, key_serial_t base, char *buffer, size_t buflen)
    long keyctl_dh_compute_alloc(key_serial_t priv, key_serial_t prime, key_serial_t base, void **_buffer)
    long keyctl_dh_compute_kdf(key_serial_t priv, key_serial_t prime, key_serial_t base,
                               char *hashname, char *otherinfo, size_t otherinfolen,
                               char *buffer, size_t buflen)

    long keyctl_pkey_query(key_serial_t key, const char *info, t.keyctl_pkey_query *result)
    long keyctl_pkey_encrypt(key_serial_t key, const char *info,
                             const void *data, size_t data_len,
                             void *enc, size_t enc_len)
    long keyctl_pkey_decrypt(key_serial_t key, const char *info,
                             const void *enc, size_t enc_len,
                             void *data, size_t data_len)
    long keyctl_pkey_sign(key_serial_t key, const char *info,
                          const void *data, size_t data_len,
                          void *sig, size_t sig_len)
    long keyctl_pkey_verify(key_serial_t key, const char *info,
                            const void *data, size_t data_len,
                            const void *sig, size_t sig_len)

    long keyctl_watch_key(key_serial_t key, int watch_queue_fd, int watch_id)

    enum:
        KEY_SPEC_THREAD_KEYRING                 = -1
        KEY_SPEC_PROCESS_KEYRING                = -2
        KEY_SPEC_SESSION_KEYRING                = -3
        KEY_SPEC_USER_KEYRING                   = -4
        KEY_SPEC_USER_SESSION_KEYRING           = -5
        KEY_SPEC_GROUP_KEYRING                  = -6
        KEY_SPEC_REQKEY_AUTH_KEY                = -7
#        KEY_SPEC_REQUESTOR_KEYRING              = -8

    enum:
        KEY_REQKEY_DEFL_NO_CHANGE               = -1
        KEY_REQKEY_DEFL_DEFAULT                 =  0
        KEY_REQKEY_DEFL_THREAD_KEYRING          =  1
        KEY_REQKEY_DEFL_PROCESS_KEYRING         =  2
        KEY_REQKEY_DEFL_SESSION_KEYRING         =  3
        KEY_REQKEY_DEFL_USER_KEYRING            =  4
        KEY_REQKEY_DEFL_USER_SESSION_KEYRING    =  5
        KEY_REQKEY_DEFL_GROUP_KEYRING           =  6

    enum:
        KEYCTL_GET_KEYRING_ID                   = 0
        KEYCTL_JOIN_SESSION_KEYRING             = 1
        KEYCTL_UPDATE                           = 2
        KEYCTL_REVOKE                           = 3
        KEYCTL_CHOWN                            = 4
        KEYCTL_SETPERM                          = 5
        KEYCTL_DESCRIBE                         = 6
        KEYCTL_CLEAR                            = 7
        KEYCTL_LINK                             = 8
        KEYCTL_UNLINK                           = 9
        KEYCTL_SEARCH                           = 10
        KEYCTL_READ                             = 11
        KEYCTL_INSTANTIATE                      = 12
        KEYCTL_NEGATE                           = 13
        KEYCTL_SET_REQKEY_KEYRING               = 14
        KEYCTL_SET_TIMEOUT                      = 15
        KEYCTL_ASSUME_AUTHORITY                 = 16
        KEYCTL_GET_SECURITY                     = 17
        KEYCTL_SESSION_TO_PARENT                = 18
        KEYCTL_REJECT                           = 19
        KEYCTL_INSTANTIATE_IOV                  = 20
        KEYCTL_INVALIDATE                       = 21
        KEYCTL_GET_PERSISTENT                   = 22
        KEYCTL_DH_COMPUTE                       = 23
        KEYCTL_MOVE                             = 24
        KEYCTL_CAPABILITIES                     = 25
        KEYCTL_PKEY_QUERY                       = 26
        KEYCTL_PKEY_ENCRYPT                     = 27
        KEYCTL_PKEY_DECRYPT                     = 28
        KEYCTL_PKEY_SIGN                        = 29
        KEYCTL_PKEY_VERIFY                      = 30
        KEYCTL_WATCH_KEY                        = 31

    enum:
        KEY_POS_VIEW	                        = 0x01000000
        KEY_POS_READ	                        = 0x02000000
        KEY_POS_WRITE	                        = 0x04000000
        KEY_POS_SEARCH	                        = 0x08000000
        KEY_POS_LINK	                        = 0x10000000
        KEY_POS_SETATTR	                        = 0x20000000
        KEY_POS_ALL 	                        = 0x3f000000
        KEY_USR_VIEW	                        = 0x00010000
        KEY_USR_READ	                        = 0x00020000
        KEY_USR_WRITE	                        = 0x00040000
        KEY_USR_SEARCH	                        = 0x00080000
        KEY_USR_LINK	                        = 0x00100000
        KEY_USR_SETATTR	                        = 0x00200000
        KEY_USR_ALL	                            = 0x003f0000
        KEY_GRP_VIEW	                        = 0x00000100
        KEY_GRP_READ	                        = 0x00000200
        KEY_GRP_WRITE	                        = 0x00000400
        KEY_GRP_SEARCH	                        = 0x00000800
        KEY_GRP_LINK	                        = 0x00001000
        KEY_GRP_SETATTR	                        = 0x00002000
        KEY_GRP_ALL	                            = 0x00003f00
        KEY_OTH_VIEW	                        = 0x00000001
        KEY_OTH_READ	                        = 0x00000002
        KEY_OTH_WRITE	                        = 0x00000004
        KEY_OTH_SEARCH	                        = 0x00000008
        KEY_OTH_LINK	                        = 0x00000010
        KEY_OTH_SETATTR	                        = 0x00000020
        KEY_OTH_ALL	                            = 0x0000003f
