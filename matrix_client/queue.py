# -*- coding: utf-8 -*-
# Copyright 2017 Adam Beckmeyer
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import gevent.queue
from gevent.event import AsyncResult
import time
import json
from .errors import MatrixRequestError


class RequestQueue(gevent.queue.Queue):
    """Queue for callbacks calling the Matrix api.

    `RequestQueue` is a FIFO queue to be consumed by gevent threads calling the
    `call` method. All objects put on the queue should be a tuple of len 2.
    First object should be a callable, and second object should be a
    gevent.event.AsyncResult.

    Other than the `call` and `call_forever` methods, it shares its api with
    `gevent.queue.Queue`.

    Usage:
        matrix = MatrixHttpApi("https://matrix.org", token="foobar")
        a = AsyncResult()
        queue = ResponseQueue()
        queue.put(matrix.sync, a)
        queue.call()
        print(a.get())
    """

    def call(self):
        """Calls two callback tuple returned by self.get().

        If instructed by server, will retry callback. Exponential backoff has
        not yet been implemented.
        """
        # If queue empty, thread blocks here
        callback, future = self.get()
        retry = True
        while retry:
            try:
                output = callback()
                future.set(output)
            except Exception as e:
                # Only handle exceptions if MatrixRequestError and status_code == 429
                if (type(e) == MatrixRequestError) and (e.code == 429):
                    time.sleep(json.loads(e.content)["retry_after_ms"] / 1000)
                else:
                    # TODO: log exceptions
                    # TODO: allow specification of exception handler
                    future.set_exception(e)
            else:
                # If api_call doesn't raise exception, we don't need to retry
                retry = False

    def call_forever(self):
        """Calls self.call forever."""
        while True:
            self.call()

    def matrix_put(self, item, *args, **kwargs):
        """Calls `self.put` after validating type of item."""
        if (type(item) == tuple and len(item) == 2 and
            callable(item[0]) and type(item[1]) == AsyncResult):

            return self.put(item, *args, **kwargs)
        else:
            raise TypeError("Received %s when expecting (callable, AsyncResult)" % str(item))
