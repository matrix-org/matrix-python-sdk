This is a Matrix client-server SDK for Python 2.x.

Usage
=====
The SDK provides 2 layers of interaction. The low-level layer just wraps the
raw HTTP API calls. The high-level layer wraps the low-level layer and provides
an object model to perform actions on.

Client:

.. code:: python

    from matrix_client.client import MatrixClient

    client = MatrixClient("http://localhost:8008")
    token = client.register_with_password(username="foobar", password="monkey")
    room = client.create_room("my_room_alias")
    room.send_text("Hello!")


API:

.. code:: python

    from matrix_client.api import MatrixHttpApi

    matrix = MatrixHttpApi("https://matrix.org", token="some_token")
    response = matrix.initial_sync()
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
