Matrix Client SDK for Python
============================

.. image:: https://img.shields.io/pypi/v/matrix-client.svg?maxAge=2592000
  :target: https://pypi.python.org/pypi/matrix-client
  :alt: Latest Version
.. image:: https://travis-ci.org/matrix-org/matrix-python-sdk.svg?branch=master
  :target: https://travis-ci.org/matrix-org/matrix-python-sdk
  :alt: Travis-CI Results
.. image:: https://coveralls.io/repos/github/matrix-org/matrix-python-sdk/badge.svg?branch=master
  :target: https://coveralls.io/github/matrix-org/matrix-python-sdk?branch=master
  :alt: coveralls.io Results


This is a Matrix client-server SDK for Python 2.7 and 3.4+

Installation
=====
Stable release
-----
Install with pip from pypi. This will install all necessary dependencies as well.

.. code:: shell

   pip install matrix_client

Development version
-----
Install using ``setup.py`` in root project directory. This will also install all
needed dependencies.

.. code:: shell

   git clone https://github.com/matrix-org/matrix-python-sdk.git
   cd matrix-python-sdk
   python setup.py install

Usage
=====
The SDK provides 2 layers of interaction. The low-level layer just wraps the
raw HTTP API calls. The high-level layer wraps the low-level layer and provides
an object model to perform actions on.

Client:

.. code:: python

    from matrix_client.client import MatrixClient

    client = MatrixClient("http://localhost:8008")

    # New user
    token = client.register_with_password(username="foobar", password="monkey")

    # Existing user
    token = client.login_with_password(username="foobar", password="monkey")

    room = client.create_room("my_room_alias")
    room.send_text("Hello!")


API:

.. code:: python

    from matrix_client.api import MatrixHttpApi

    matrix = MatrixHttpApi("https://matrix.org", token="some_token")
    response = matrix.send_message("!roomid:matrix.org", "Hello!")


Structure
=========
The SDK is split into two modules: ``api`` and ``client``.

API
---
This contains the raw HTTP API calls and has minimal business logic. You can
set the access token (``token``) to use for requests as well as set a custom
transaction ID (``txn_id``) which will be incremented for each request.

Client
------
This encapsulates the API module and provides object models such as ``Room``.

Samples
=======
A collection of samples are included, written in Python 3.

You can either install the SDK, or run the sample like this:

.. code:: shell

    PYTHONPATH=. python samples/samplename.py

Building the Documentation
==========================

The documentation can be built by installing ``sphinx`` and ``sphinx_rtd_theme``.

Simple run ``make`` inside ``docs`` which will list the avaliable output formats.
