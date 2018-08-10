Overview of end-to-end encryption in matrix-python-sdk
------------------------------------------------------

This SDK supports end-to-end encryption as specified in Matrix. The following is an
overview of the main available features.

Encryption is mostly automatic, and users are not expected to read past the `basic
usage`_ section.

.. contents::

Installation
============

Encryption requires `libolm`__, the official Matrix library that provides the necessary
cryptographic primitives. It is available in many Linux distribution repositories, and can
also be easily compiled from source.

__ https://matrix.org/git/olm

Encryption also comes with several optional dependencies, listed under the ``e2e`` group
in ``setup.py``.

Using pip, these can be installed by running ``pip install .[e2e]`` at the root of the
repository.

Encryption heavily rely on an underlying database, in order to work seamlessly across
restarts. This is implemented using SQLite and the sqlite3 module of the standard Python
library. Users do not not have to worry about this, and the database location is platform
dependent (and is displayed on start-up via an info log line). For advanced usage, see
`overriding the crypto store`_.


Basic usage
===========

Encryption support is disabled by default. Enabling it is done when instantiating
``MatrixClient``, as follow:

.. code:: python

  client = MatrixClient(HOSTNAME, encryption=True)

.. note::

  When enabling encryption in an already existing project, you will notice that a lot of
  logging messages appear. Most of those can be safely ignored. For instance, warning
  messages on first sync simply mean that the client is unable to decrypt old messages
  it didn't receive the keys for, as there are anterior to the encryption enabling.

Device IDs
~~~~~~~~~~

When using encryption, a user **should** reuse device IDs, as they are associated with
a fingerprint key that should not change across restart, in most cases. The complete
rationale is explained `here`__.

__ https://matrix.org/docs/guides/e2e_implementation.html#devices

A user can keep track of device IDs by specifying them at login, or can delegate it to the
SDK, as follow:

.. code:: python

  client = MatrixClient(HOSTNAME, encryption=True, restore_device_id=True)

On first launch, the client will store the device ID returned by the homeserver in the
same database used to store encryption keys. On subsequent launches, the device ID will be
retrieved from the user ID at login.

.. note::

  When logging in with ``restore_device_id`` turned on, you must supply a full user ID (eg ``@test:matrix.org``), not just a username (eg ``test``).

When using this, the need to reset the device ID automatically associated with a user ID
may arise. This can be done by explicitly specifying a device ID at login, or simply by
removing the database (consider using ``shred`` over ``rm``). Both of these methods will
delete all the encryption data associated with the previous device, as none can be safely
reused as-is with a new one. Hence, before doing this, a user might want to `export
encryption keys`_.

.. note::
  
  Refer to ``samples/e2e_overview.py`` for more example code.


Advanced usage
==============

Several options are available in order to customize some behaviors, or to enable
additional features. These are abundantly documented via docstrings, and the following
subsections aim at showing some examples.

Device verification
~~~~~~~~~~~~~~~~~~~

A major feature of end-to-end encryption is to make sure that the sender of a message is
the actual sender, and not an usurper.

In order to allow other users to verify the current device, its fingerprint should be
displayed. This is done by calling ``client.get_fingerprint()``.

Device verification is disabled by default. It can be enabled globally by passing
``verify_devices=True`` when instantiating ``MatrixClient``, or on a per-room basis by
doing ``room.verify_devices = True``.

Once device verification is enabled in a room, sending messages to it will raise
``E2EUnknownDevices`` if there are some never seen before devices. A user should inspect
the ``user_devices`` attribute of this exception, and for each devices it contains, do
either:

  - ``device.verified = True`` if the device can be verified. New checks will be enabled
    to ensure that every subsequent messages received from this device actually come from
    it.
  - ``device.blacklisted = True`` if decryption keys should never be shared with this
    device.
  - ``device.ignored = True`` if the device cannot be verified, and keys should be
    sent to it anyway.

Those verifications are persisted in database.

.. note::
  
  This section is incomplete (doesn't explain how to verify an event).

Key sharing
~~~~~~~~~~~

A feature of the protocol is to be able to request and receive encryption keys from other
users. The SDK implements only the sharing of keys with devices of the current Matrix
user.

Key sharing is disabled by default. A user has to implement non-trivial logic in order to
use it.

The automatic request of keys can be enabled by adding a listener using
``MatrixClient.add_key_forward_listener(callback)``. The callback should be used to be
notified when a new key arrives, and it is advised to carefully read the docstring of this
method. A client only wanting to silently request and receive keys can add a callback
which does nothing.

In order to reply to key requests, ``MatrixClient.add_key_request_listener(callback)``
should be used. Refer to the docstring for more info.

Encrypted attachments
~~~~~~~~~~~~~~~~~~~~~

.. TODO waiting for more convenient upload/download process

Export encryption keys
~~~~~~~~~~~~~~~~~~~~~~

A user may want to import or export the encryption keys used in rooms, in order to be able
to decrypt messages on a new device. This can be done by using the ``export_keys`` and
``import_keys`` methods of ``MatrixClient``.

Overriding the crypto store
~~~~~~~~~~~~~~~~~~~~~~~~~~~

In order to use another storage method, the SQLite storage can be replaced by subclassing
the class ``CryptoStore`` and carefully reimplementing all the methods, which are
thoroughly documented for this purpose. The new class can then be used as follow:

.. code:: python

  client = MatrixClient(HOSTNAME, encryption=True, encryption_conf={'Store': NewClass})

Changing the database file location
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This feature is especially useful when wanting to run several instances of
``MatrixClient`` in multiple *processes* (threads should work fine). The SQLite database
cannot be shared between processes (at least not without proper locking, which would have
to be implemented). Then the easiest way is to have one database per process.

The ``CryptoStore`` class can be passed attributes ``db_path`` and ``db_name``.
Then, configuring the database to be stored as ``/foo/bar.db`` is done as follow:

.. code:: python

  store_conf = {'db_path': '/foo/', 'db_name': 'bar.db'}
  client = MatrixClient(HOSTNAME, encryption=True,
                        encryption_conf={'store_conf': store_conf})
