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
import urllib
import urlparse

class MatrixError(Exception):
    """A generic Matrix error. Specific errors will subclass this."""
    pass


class MatrixRequestError(MatrixError):
    """ The home server returned an error response. """

    def __init__(self, code=0, content=""):
        super(MatrixRequestError, self).__init__("%d: %s" % (code, content))
        self.code = code
        self.content = content


class MatrixHttpApi(object):
    """Contains all raw Matrix HTTP Client-Server API calls.

    Usage:
        matrix = MatrixHttpApi("https://matrix.org", token="foobar")
        response = matrix.initial_sync()
        response = matrix.send_message("!roomid:matrix.org", "Hello!")

    For room and sync handling, consider using MatrixClient.
    """

    def __init__(self, base_url, token=None):
        """Construct and configure the HTTP API.

        Args:
            base_url(str): The home server URL e.g. 'http://localhost:8008'
            token(str): Optional. The client's access token.
        """
        if not base_url.endswith("/_matrix/client/api/v1"):
            self.url = urlparse.urljoin(base_url, "/_matrix/client/api/v1")
        else:
            self.url = base_url
        self.token = token
        self.txn_id = 0

    def initial_sync(self, limit=1):
        """Perform /initialSync.

        Args:
            limit(int): The limit= param to provide.
        """
        return self._send("GET", "/initialSync", query_params={"limit": limit})

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

        path = "/join/%s" % room_id_or_alias

        return self._send("POST", path)

    def event_stream(self, from_token, timeout=30000):
        """Performs /events

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
        path = ("/rooms/%s/state/%s" %
            (urllib.quote(room_id), urllib.quote(event_type))
        )
        if state_key:
            path += "/%s" % (urllib.quote(state_key))
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
            txn_id = self.txn_id

        self.txn_id = self.txn_id + 1

        path = ("/rooms/%s/send/%s/%s" %
            (urllib.quote(room_id), urllib.quote(event_type),
             urllib.quote(unicode(txn_id)))
        )
        return self._send("PUT", path, content)

    def send_message(self, room_id, text_content):
        """Perform /rooms/$room_id/send/m.room.message

        Args:
            room_id(str): The room ID to send the event in.
            text_content(str): The m.text body to send.
        """
        return self.send_message_event(
            room_id, "m.room.message",
            self.get_text_body(text_content)
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

    def get_room_name(self, room_id):
        """Perform GET /rooms/$room_id/state/m.room.name
        Args:
            room_id(str): The room ID
        """
        return self._send("GET", "/rooms/" + room_id + "/state/m.room.name")

    def get_room_topic(self, room_id):
        """Perform GET /rooms/$room_id/state/m.room.topic
        Args:
            room_id(str): The room ID
        """
        return self._send("GET", "/rooms/" + room_id + "/state/m.room.topic")

    def leave_room(self, room_id):
        """Perform POST /rooms/$room_id/leave
        Args:
            room_id(str): The room ID
        """
        return self._send("POST", "/rooms/" + room_id + "/leave")

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

    def kick_user(self, room_id, user_id):
        """Perform POST /rooms/$room_id/kick
        Args:
            room_id(str): The room ID
            user_id(str): The user ID of the kickee(sic)
        """
        body = {
            "user_id": user_id
        }
        return self._send("POST", "/rooms/" + room_id + "/kick", body)

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

    def get_room_state(self, room_id):
        """Perform GET /rooms/$room_id/state
        Args:
            room_id(str): The room ID
        """
        return self._send("GET", "/rooms/" + room_id + "/state")

    def get_text_body(self, text):
        return {
            "msgtype": "m.text",
            "body": text
        }

    def get_html_body(self, html):
        return {
            "body": re.sub('<[^<]+?>', '', html),
            "msgtype": "m.text",
            "format": "org.matrix.custom.html",
            "formatted_body": html
        }

    def get_emote_body(self, text):
        return {
            "msgtype": "m.emote",
            "body": text
        }

    def _send(self, method, path, content=None, query_params={}, headers={}):
        method = method.upper()
        if method not in ["GET", "PUT", "DELETE", "POST"]:
            raise MatrixError("Unsupported HTTP method: %s" % method)

        headers["Content-Type"] = "application/json"
        query_params["access_token"] = self.token
        endpoint = self.url + path

        response = requests.request(
            method, endpoint, params=query_params,
            data=json.dumps(content), headers=headers
            # , verify=False  #if you want to use SSL without verifying the Cert
        )

        if response.status_code < 200 or response.status_code >= 300:
            raise MatrixRequestError(
                code=response.status_code, content=response.text
            )

        return response.json()
