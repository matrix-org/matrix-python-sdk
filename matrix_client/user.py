# -*- coding: utf-8 -*-
# Copyright 2015 OpenMarket Ltd
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
from warnings import warn

from .checks import check_user_id
from .device import Device


class User(object):
    """ The User class can be used to call user specific functions.
    """
    def __init__(self, client, user_id, displayname=None):
        check_user_id(user_id)

        self.user_id = user_id
        self.displayname = displayname
        self.client = client
        self._devices = {}

    def get_display_name(self, room=None):
        """Get this user's display name.

        Args:
            room (Room): Optional. When specified, return the display name of the user
                in this room.

        Returns:
            The display name. Defaults to the user ID if not set.
        """
        if room:
            try:
                return room.members_displaynames[self.user_id]
            except KeyError:
                return self.user_id
        if not self.displayname:
            self.displayname = self.client.api.get_display_name(self.user_id)
        return self.displayname or self.user_id

    def get_friendly_name(self):
        """Deprecated. Use :meth:`get_display_name` instead."""
        warn("get_friendly_name is deprecated. Use get_display_name instead.",
             DeprecationWarning)
        return self.get_display_name()

    def set_display_name(self, display_name):
        """ Set this users display name.

        Args:
            display_name (str): Display Name
        """
        self.displayname = display_name
        return self.client.api.set_display_name(self.user_id, display_name)

    def get_avatar_url(self):
        mxcurl = self.client.api.get_avatar_url(self.user_id)
        url = None
        if mxcurl is not None:
            url = self.client.api.get_download_url(mxcurl)
        return url

    def set_avatar_url(self, avatar_url):
        """ Set this users avatar.

        Args:
            avatar_url (str): mxc url from previously uploaded
        """
        return self.client.api.set_avatar_url(self.user_id, avatar_url)

    @property
    def devices(self):
        # If this user is joined in an encrypted room with us, we may already have an
        # up-to-date list of their devices.
        if self.client._encryption and \
                self.user_id in self.client.olm_device.device_list.tracked_user_ids:

            if self.user_id not in self.client.device_keys:
                self.client.db.get_device_keys(
                    self.client.api, {self.user_id: []}, self.client.device_keys
                )
            self._devices = self.client.device_keys[self.user_id]
        else:
            devices = self.client.api.query_keys({self.user_id: []})["device_keys"]
            for device_id in devices:
                if device_id not in self._devices:
                    # Do not add the keys even if they are in the payload, because
                    # we are not able to verify them right know. This means that device
                    # verification will only become available once we share an encrypted
                    # room with this user.
                    self._devices[device_id] = Device(self.client.api, device_id)

        for device in self._devices:
            device.get_info()

        # Returning a copy prevents adding/removing devices while allowing to verify or
        # blacklist them.
        return self._devices.copy()
