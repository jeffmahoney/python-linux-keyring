"""Keyring Backend that uses the Linux Kernel Keyring via keyutils"""

import errno
from typing import Union, Optional
import keyring.backend
import keyring.errors
from jaraco.classes import properties

from . import libkeyutils
from .libkeyutils import key_serial_t

KeyringID = Union[key_serial_t, str]

THREAD_KEYRING = libkeyutils.KEY_SPEC_THREAD_KEYRING
PROCESS_KEYRING = libkeyutils.KEY_SPEC_PROCESS_KEYRING
SESSION_KEYRING = libkeyutils.KEY_SPEC_SESSION_KEYRING
USER_KEYRING = libkeyutils.KEY_SPEC_THREAD_KEYRING
USER_SESSION_KEYRING = libkeyutils.KEY_SPEC_THREAD_KEYRING
GROUP_KEYRING = libkeyutils.KEY_SPEC_THREAD_KEYRING

builtin_keys = {
    "@t":                   THREAD_KEYRING,
    "thread_keyring":       THREAD_KEYRING,
    "@p":                   PROCESS_KEYRING,
    "process_keyring":      PROCESS_KEYRING,
    "@s":                   SESSION_KEYRING,
    "session_keyring":      SESSION_KEYRING,
    "@u":                   USER_KEYRING,
    "user_keyring":         USER_KEYRING,
    "@us":                  USER_SESSION_KEYRING,
    "user_session_keyring": USER_SESSION_KEYRING,
    "@g":                   GROUP_KEYRING,
    "group_keyring":        GROUP_KEYRING,
}


class LinuxKernelKeyringMissingKey(keyring.errors.KeyringError):
    """Key is not in the Kernel Keyring"""


class InvalidEmptyPasswordError(keyring.errors.PasswordSetError):
    """Kernel Keyring does not support empty passwords"""


class LinuxKernelKeyringBackend(keyring.backend.KeyringBackend):
    """A Keyring Backend that uses the Linux Kernel Keyring"""
    def __init__(self, keyring_id: KeyringID = "python-linux-keyring-backend",
                 parent_keyring: KeyringID = SESSION_KEYRING,
                 key_type: str = 'user'):
        super().__init__()

        parent_keyring_id: key_serial_t
        if isinstance(parent_keyring, str):
            try:
                parent_keyring_id = builtin_keys[parent_keyring]
            except KeyError:
                try:
                    parent_keyring_id = key_serial_t(parent_keyring)
                except ValueError as e:
                    # pylint: disable=line-too-long
                    raise keyring.errors.InitError(f"Failed to translate parent_keyring \"{parent_keyring}\" to usable keyring ID") from e
        else:
            parent_keyring_id = parent_keyring

        keyring_key: key_serial_t = 0
        keyring_name: str
        if isinstance(keyring_id, str):
            keyring_name = keyring_id
            try:
                keyring_key = libkeyutils.keyctl_search(parent_keyring_id,
                                                        "keyring", keyring_name,
                                                        parent_keyring_id)
            except OSError as e:
                if e.errno != errno.ENOKEY:
                    # pylint: disable=line-too-long
                    raise keyring.errors.InitError(f"Failed to find/create keyring \"{keyring_name}\" in parent keyring {parent_keyring_id}: {e.strerror}")

            if keyring_key == 0:
                keyring_key = libkeyutils.add_key("keyring", keyring_name, None, parent_keyring_id)
        else:
            keyring_key = keyring_id
            try:
                keyring_name = libkeyutils.keyctl_describe(keyring_key)
            except OSError as e:
                # pylint: disable=line-too-long
                raise keyring.errors.InitError(f"Failed to find/create keyring \"{keyring_name}\" in parent keyring {parent_keyring_id}: {e.strerror}")

        self._keyring_name = keyring_name
        self._keyring_id = keyring_key
        self._parent_keyring = parent_keyring_id
        self._key_type = key_type

    @properties.classproperty
    def priority(self) -> float:
        return 1

    def _format_key(self, service: str, username: str) -> str:
        return f"{service}:{username}"

    def _search_key(self, description: str) -> key_serial_t:
        try:
            return libkeyutils.keyctl_search(self._keyring_id, self._key_type,
                                             description, 0)
        except OSError as e:
            if e.errno in (errno.EKEYREVOKED, errno.EKEYEXPIRED, errno.ENOKEY):
                # pylint: disable=line-too-long
                raise LinuxKernelKeyringMissingKey(f"Couldn't locate key with description {description}: {e.strerror}") from e
            raise e from e

    def get_password(self, service: str, username: str) -> Optional[str]:
        try:
            description = self._format_key(service, username)
            key = self._search_key(description)
        except LinuxKernelKeyringMissingKey:
            return None

        return libkeyutils.keyctl_read_as_str(key)

    def set_password(self, service: str, username: str, password: str) -> None:
        description = self._format_key(service, username)
        try:
            libkeyutils.add_key(self._key_type, description,
                                password.encode('utf-8'),
                                self._keyring_id)
        except OSError as e:
            if e.errno == errno.EINVAL and not password:
                # pylint: disable=line-too-long
                raise InvalidEmptyPasswordError(f"Failed to add key with description {description}: Key type {self._key_type} does not support empty payloads.") from e
            # pylint: disable=line-too-long
            raise keyring.errors.PasswordSetError(f"Failed to add key with description {description}: {e.strerror}") from e

    def delete_password(self, service: str, username: str) -> None:
        description = self._format_key(service, username)
        try:
            key = self._search_key(description)
            libkeyutils.keyctl_invalidate(key)
        except LinuxKernelKeyringMissingKey as e:
            # pylint: disable=line-too-long
            raise keyring.errors.PasswordDeleteError(f"Failed to locate key with description {description}") from e
        except OSError as e:
            # pylint: disable=line-too-long
            raise keyring.errors.PasswordDeleteError(f"Failed to delete key with description {description}: {e.strerror}") from e
