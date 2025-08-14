
Errors & Exceptions
===================

Most operations raise :class:`OSError` when the underlying syscall fails. The
``errno`` is propagated from the kernel. Common values include:

- ``ENOENT`` (No such key) when searching for a missing key.
- ``EACCES`` or ``EPERM`` on permission failures.
- ``EKEYREVOKED``/``EKEYEXPIRED`` for revoked/expired keys.

Capture the error code like so:

.. code-block:: python

   import errno
   try:
       ku.keyctl_read_alloc(0)  # invalid serial
   except OSError as e:
       assert e.errno in {errno.ENOENT, errno.EINVAL}
