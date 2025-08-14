cdef extern from "sys/uio.h":
    ctypedef struct iovec "struct iovec":
        void *iov_base
        size_t iov_len

cdef extern from "<keyutils.h>":
    ctypedef struct keyctl_pkey_query "struct keyctl_pkey_query":
        unsigned int supported_ops
        unsigned int key_size
        unsigned short max_data_size
        unsigned short max_sig_size
        unsigned short max_enc_size
        unsigned short max_dec_size


