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

import json
import re
import requests
from time import time, sleep
from .errors import MatrixError, MatrixRequestError

try:
    from urllib import quote
except ImportError:
    from urllib.parse import quote


class MatrixHttpApi(object):
    """Contains all raw Matrix HTTP Client-Server API calls.

    Usage:
        matrix = MatrixHttpApi("https://matrix.org", token="foobar")
        response = matrix.sync()
        response = matrix.send_message("!roomid:matrix.org", "Hello!")

    For room and sync handling, consider using MatrixClient.
    """

    def __init__(self, base_url, token=None):
        """Construct and configure the HTTP API.

        Args:
            base_url(str): The home server URL e.g. 'http://localhost:8008'
            token(str): Optional. The client's access token.
        """
        self.base_url = base_url
        self.token = token
        self.txn_id = 0
        self.validate_cert = True

    def initial_sync(self, limit=1):
        """ Deprecated. Use sync instead.
        Perform /initialSync.

        Args:
            limit(int): The limit= param to provide.
        """
        return self._send("GET", "/initialSync", query_params={"limit": limit})

    def sync(self, since=None, timeout_ms=30000, filter=None,
             full_state=None, set_presence=None):
        """ Perform a sync request.

        Args:
            since(str): Optional. A token which specifies where to continue
                a sync from.
            timeout_ms(int): Optional. The time in milliseconds to wait.
            filter (int|str): Either a Filter ID or a JSON string.
            full_state (bool): Return the full state for every room the user has joined
                Defaults to false.
            set_presence (str): Should the client be marked as "online" or" offline"
        """

        request = {
            "timeout": timeout_ms
        }

        if since:
            request["since"] = since

        if filter:
            request["filter"] = filter

        if full_state:
            request["full_state"] = full_state

        if set_presence:
            request["set_presence"] = set_presence

        return self._send("GET", "/sync", query_params=request,
                          api_path="/_matrix/client/r0")

    def validate_certificate(self, valid):
        self.validate_cert = valid
        return

    def register(self, login_type, **kwargs):
        """Performs /register.

        Args:
            login_type(str): The value for the 'type' key.
            **kwargs: Additional key/values to add to the JSON submitted.
        """
        content = {
            "type": login_type
        }
        for key in kwargs:
            content[key] = kwargs[key]

        return self._send("POST", "/register", content)

    def login(self, login_type, **kwargs):
        """Perform /login.

        Args:
            login_type(str): The value for the 'type' key.
            **kwargs: Additional key/values to add to the JSON submitted.
        """
        content = {
            "type": login_type
        }
        for key in kwargs:
            content[key] = kwargs[key]

        return self._send("POST", "/login", content)

    def create_room(self, alias=None, is_public=False, invitees=()):
        """Perform /createRoom.

        Args:
            alias(str): Optional. The room alias name to set for this room.
            is_public(bool): Optional. The public/private visibility.
            invitees(list<str>): Optional. The list of user IDs to invite.
        """
        content = {
            "visibility": "public" if is_public else "private"
        }
        if alias:
            content["room_alias_name"] = alias
        if invitees:
            content["invite"] = invitees
        return self._send("POST", "/createRoom", content)

    def join_room(self, room_id_or_alias):
        """Performs /join/$room_id

        Args:
            room_id_or_alias(str): The room ID or room alias to join.
        """
        if not room_id_or_alias:
            raise MatrixError("No alias or room ID to join.")

        path = "/join/%s" % quote(room_id_or_alias)

        return self._send("POST", path)

    def event_stream(self, from_token, timeout=30000):
        """ Deprecated. Use sync instead.
        Performs /events

        Args:
            from_token(str): The 'from' query parameter.
            timeout(int): Optional. The 'timeout' query parameter.
        """
        path = "/events"
        return self._send(
            "GET", path, query_params={
                "timeout": timeout,
                "from": from_token
            }
        )

    def send_state_event(self, room_id, event_type, content, state_key=""):
        """Perform /rooms/$room_id/state/$event_type

        Args:
            room_id(str): The room ID to send the state event in.
            event_type(str): The state event type to send.
            content(dict): The JSON content to send.
            state_key(str): Optional. The state key for the event.
        """
        path = "/rooms/%s/state/%s" % (
            quote(room_id), quote(event_type),
        )
        if state_key:
            path += "/%s" % (quote(state_key))
        return self._send("PUT", path, content)

    def send_message_event(self, room_id, event_type, content, txn_id=None):
        """Perform /rooms/$room_id/send/$event_type

        Args:
            room_id(str): The room ID to send the message event in.
            event_type(str): The event type to send.
            content(dict): The JSON content to send.
            txn_id(int): Optional. The transaction ID to use.
        """
        if not txn_id:
            txn_id = str(self.txn_id) + str(int(time() * 1000))

        self.txn_id = self.txn_id + 1

        path = "/rooms/%s/send/%s/%s" % (
            quote(room_id), quote(event_type), quote(str(txn_id)),
        )
        return self._send("PUT", path, content)

    # content_type can be a image,audio or video
    # extra information should be supplied, see
    # https://matrix.org/docs/spec/r0.0.1/client_server.html
    def send_content(self, room_id, item_url, item_name, msg_type,
                     extra_information=None):
        if extra_information is None:
            extra_information = {}

        content_pack = {
            "url": item_url,
            "msgtype": msg_type,
            "body": item_name,
            "info": extra_information
        }
        return self.send_message_event(room_id, "m.room.message", content_pack)

    def send_message(self, room_id, text_content, msgtype="m.text"):
        """Perform /rooms/$room_id/send/m.room.message

        Args:
            room_id(str): The room ID to send the event in.
            text_content(str): The m.text body to send.
        """
        return self.send_message_event(
            room_id, "m.room.message",
            self.get_text_body(text_content, msgtype)
        )

    def send_emote(self, room_id, text_content):
        """Perform /rooms/$room_id/send/m.room.message with m.emote msgtype

        Args:
            room_id(str): The room ID to send the event in.
            text_content(str): The m.emote body to send.
        """
        return self.send_message_event(
            room_id, "m.room.message",
            self.get_emote_body(text_content)
        )

    def send_notice(self, room_id, text_content):
        """Perform /rooms/$room_id/send/m.room.message with m.notice msgtype

        Args:
            room_id(str): The room ID to send the event in.
            text_content(str): The m.notice body to send.
        """
        body = {
            "msgtype": "m.notice",
            "body": text_content
        }
        return self.send_message_event(room_id, "m.room.message", body)

    def get_room_name(self, room_id):
        """Perform GET /rooms/$room_id/state/m.room.name
        Args:
            room_id(str): The room ID
        """
        return self._send("GET", "/rooms/" + room_id + "/state/m.room.name")

    def set_room_name(self, room_id, name):
        """Perform PUT /rooms/$room_id/state/m.room.name
        Args:
            room_id(str): The room ID
            name(str): The new room name
        """
        body = {
            "name": name
        }
        return self._send("PUT", "/rooms/" + room_id + "/state/m.room.name", body)

    def get_room_topic(self, room_id):
        """Perform GET /rooms/$room_id/state/m.room.topic
        Args:
            room_id(str): The room ID
        """
        return self._send("GET", "/rooms/" + room_id + "/state/m.room.topic")

    def set_room_topic(self, room_id, topic):
        """Perform PUT /rooms/$room_id/state/m.room.topic
        Args:
            room_id(str): The room ID
            topic(str): The new room topic
        """
        body = {
            "topic": topic
        }
        return self._send("PUT", "/rooms/" + room_id + "/state/m.room.topic", body)

    def leave_room(self, room_id):
        """Perform POST /rooms/$room_id/leave
        Args:
            room_id(str): The room ID
        """
        return self._send("POST", "/rooms/" + room_id + "/leave", {})

    def invite_user(self, room_id, user_id):
        """Perform POST /rooms/$room_id/invite
        Args:
            room_id(str): The room ID
            user_id(str): The user ID of the invitee
        """
        body = {
            "user_id": user_id
        }
        return self._send("POST", "/rooms/" + room_id + "/invite", body)

    def kick_user(self, room_id, user_id, reason=""):
        """Calls set_membership with membership="leave" for the user_id provided
        """
        self.set_membership(room_id, user_id, "leave", reason)

    def set_membership(self, room_id, user_id, membership, reason=""):
        """Perform PUT /rooms/$room_id/state/m.room.member/$user_id
        Args:
            room_id(str): The room ID
            user_id(str): The user ID
            membership(str): New membership value
            reason(str): The reason
        """
        body = {
            "membership": membership,
            "reason": reason
        }
        return self._send(
            "PUT",
            "/rooms/%s/state/m.room.member/%s" % (room_id, user_id),
            body
        )

    def ban_user(self, room_id, user_id, reason=""):
        """Perform POST /rooms/$room_id/ban
        Args:
            room_id(str): The room ID
            user_id(str): The user ID of the banee(sic)
            reason(str): The reason for this ban
        """
        body = {
            "user_id": user_id,
            "reason": reason
        }
        return self._send("POST", "/rooms/" + room_id + "/ban", body)

    def get_user_tags(self, user_id, room_id):
        return self._send(
            "GET",
            "/user/%s/rooms/%s/tags" % (user_id, room_id),
            api_path="/_matrix/client/r0"
        )

    def remove_user_tag(self, user_id, room_id, tag):
        return self._send(
            "DELETE",
            "/user/%s/rooms/%s/tags/%s" % (user_id, room_id, tag),
            api_path="/_matrix/client/r0"
        )

    def add_user_tag(self, user_id, room_id, tag, order=None, body=None):
        if body:
            pass
        elif order:
            body = {"order": order}
        else:
            body = {}
        return self._send(
            "PUT",
            "/user/%s/rooms/%s/tags/%s" % (user_id, room_id, tag),
            body,
            api_path="/_matrix/client/r0"
        )

    def set_account_data(self, user_id, type, account_data):
        return self._send(
            "PUT",
            "/user/%s/account_data/%s" % (user_id, type),
            account_data,
            api_path="/_matrix/client/r0"
        )

    def set_room_account_data(self, user_id, room_id, type, account_data):
        return self._send(
            "PUT",
            "/user/%s/rooms/%s/account_data/%s" % (user_id, room_id, type),
            account_data,
            api_path="/_matrix/client/r0"
        )

    def get_room_state(self, room_id):
        """Perform GET /rooms/$room_id/state
        Args:
            room_id(str): The room ID
        """
        return self._send("GET", "/rooms/" + room_id + "/state")

    def get_text_body(self, text, msgtype="m.text"):
        return {
            "msgtype": msgtype,
            "body": text
        }

    def get_html_body(self, html, msgtype="m.text"):
        return {
            "body": re.sub('<[^<]+?>', '', html),
            "msgtype": msgtype,
            "format": "org.matrix.custom.html",
            "formatted_body": html
        }

    def get_emote_body(self, text):
        return {
            "msgtype": "m.emote",
            "body": text
        }

    def _send(self, method, path, content=None, query_params={}, headers={},
              api_path="/_matrix/client/api/v1"):
        method = method.upper()
        if method not in ["GET", "PUT", "DELETE", "POST"]:
            raise MatrixError("Unsupported HTTP method: %s" % method)

        if "Content-Type" not in headers:
            headers["Content-Type"] = "application/json"

        query_params["access_token"] = self.token
        endpoint = self.base_url + api_path + path

        if headers["Content-Type"] == "application/json":
            content = json.dumps(content)

        response = None
        while True:
            response = requests.request(
                method, endpoint,
                params=query_params,
                data=content,
                headers=headers,
                verify=self.validate_cert
            )

            if response.status_code == 429:
                sleep(response.json()['retry_after_ms'] / 1000)
            else:
                break

        if response.status_code < 200 or response.status_code >= 300:
            raise MatrixRequestError(
                code=response.status_code, content=response.text
            )

        return response.json()

    def media_upload(self, content, content_type):
        return self._send(
            "POST", "",
            content=content,
            headers={"Content-Type": content_type},
            api_path="/_matrix/media/r0/upload"
        )

    def get_display_name(self, user_id):
        content = self._send("GET", "/profile/%s/displayname" % user_id)
        return content.get('displayname', None)

    def set_display_name(self, user_id, display_name):
        content = {"displayname": display_name}
        self._send("PUT", "/profile/%s/displayname" % user_id, content)

    def get_avatar_url(self, user_id):
        content = self._send("GET", "/profile/%s/avatar_url" % user_id)
        return content.get('avatar_url', None)

    def set_avatar_url(self, user_id, avatar_url):
        content = {"avatar_url": avatar_url}
        self._send("PUT", "/profile/%s/avatar_url" % user_id, content)

    def get_download_url(self, mxcurl):
        if mxcurl.startswith('mxc://'):
            return self.base_url + "/_matrix/media/r0/download/" + mxcurl[6:]
        else:
            raise ValueError("MXC URL did not begin with 'mxc://'")

    def get_room_id(self, room_alias):
        """Get room id from its alias

        Args:
            room_alias(str): The room alias name.

        Returns:
            Wanted room's id.
        """
        content = self._send("GET", "/directory/room/{}".format(quote(room_alias)),
                             api_path="/_matrix/client/r0")
        return content.get("room_id", None)

    def get_public_rooms(self):
        """List the public rooms on the server
        """
        return self._send("GET", "/publicRooms", api_path="/_matrix/client/r0")

    def set_room_alias(self, room_id, room_alias):
        """Set alias to room id

        Args:
            room_id(str): The room id.
            room_alias(str): The room wanted alias name.
        """
        data = {
            "room_id": room_id
        }

        return self._send("PUT", "/directory/room/{}".format(quote(room_alias)),
                          content=data, api_path="/_matrix/client/r0")

    def remove_room_alias(self, room_alias):
        """Remove mapping of an alias

        Args:
            room_alias(str): The alias to be removed.

        Raises:
            MatrixRequestError
        """
        return self._send("DELETE", "/directory/room/{}".format(quote(room_alias)),
                          api_path="/_matrix/client/r0")
