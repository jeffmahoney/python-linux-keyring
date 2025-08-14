
Usage
=====

Create a session keyring, add a key, and read it back:

.. code-block:: python

   import linux-keyutils as ku

   # Join or create a named session keyring
   kr = ku.keyctl_join_session_keyring(b"example-session")

   # Add a 'user' key to the session keyring
   key = ku.add_key(b"user", b"example", b"payload", kr)

   # Read its payload
   data = ku.keyctl_read_alloc(key)
   assert data == b"payload"

Negative instantiation (request-key handlers)
---------------------------------------------

During a request-key(8) handler, you may instantiate or negatively instantiate a
pending key:

.. code-block:: python

   # Instantiate
   ku.keyctl_instantiate(pending_key_serial, b"bytes", dest_keyring)

   # Negatively instantiate for 30 seconds
   ku.keyctl_negate(pending_key_serial, 30, dest_keyring)
