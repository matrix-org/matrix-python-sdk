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
from . import errors
from .api import MatrixApi
import functools


class AggregateApi:
    """Groups together multiple Api objects to call in order."""

    def __init__(self, api_list):
        """Constructs the aggregate api to look like MatrixApi.

        Args:
            api_list(iterable): Iterable of api objects to be tried in order.
        """
        self.apis = api_list
        # Make methods of AggregateApi look like MatrixApi
        method_names = (m for m in dir(MatrixApi) if not m.startswith("_"))
        for m in method_names:
            setattr(self, m, functools.partial(self._call_api_methods, m))

    def _call_api_methods(self, method_name, *args, **kwargs):
        """Calls method of each listed api until successful.

        Args:
            method_name(str): Method to be called on each object in self.apis
            args: To be passed when calling method.
            kwargs: To be passed when calling method.
        """
        api_methods = (getattr(api, method_name) for api in self.apis)
        for method in api_methods:
            try:
                return method(*args, **kwargs)
            except NotImplementedError:
                pass

        raise errors.MatrixApiError('Unable to complete the api method', method_name)
