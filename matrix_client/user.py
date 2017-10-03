# -*- coding: utf-8 -*-
# Copyright 2015 OpenMarket Ltd
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

from functools import partial

class User(object):
    """ The User class can be used to call user specific functions.
    """
    def __init__(self, api, user_id, caller):
        if not user_id.startswith("@"):
            raise ValueError("UserIDs start with @")

        if ":" not in user_id:
            raise ValueError("UserIDs must have a domain component, seperated by a :")

        self.user_id = user_id
        self.api = api
        # Caller may be synchronous or async depending on MatrixClient creating User
        self._call = caller

    def get_display_name(self):
        """ Get this users display name.
            See also get_friendly_name()

        Returns:
            str: Display Name
            or
            AsyncResult(str)
        """
        # TODO: shouldn't this method cache the user's display name?
        return self._call(
            partial(self.api.get_display_name, self.user_id),
            # `api.get_display_name` already processes json for some reason
            lambda x: x
        )

    def get_friendly_name(self):
        # TODO: docstring
        return self._call(
            partial(self.api.get_display_name, self.user_id),
            # user_id is best identifier lacking display_name
            lambda d: d if d is not None else self.user_id
        )

    def set_display_name(self, display_name):
        """ Set this users display name.

        Args:
            display_name (str): Display Name
        """
        self._call(
            partial(self.api.set_display_name, self.user_id, display_name),
            lambda x: None
        )

    def get_avatar_url(self):
        # TODO: docstring
        return self._call(
            partial(self.api.get_avatar_url, self.user_id),
            self.api.get_download_url
        )

    def set_avatar_url(self, avatar_url):
        """ Set this users avatar.

        Args:
            avatar_url (str): mxc url from previously uploaded
        """
        self._call(
            partial(self.api.set_avatar_url, self.user_id, avatar_url),
            lambda x: None
        )
