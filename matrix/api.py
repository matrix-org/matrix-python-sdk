# -*- coding: utf-8 -*-
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
        if not base_url.endswith("/_matrix/client/api/v1"):
            self.url = urlparse.urljoin(base_url, "/_matrix/client/api/v1")
        else:
            self.url = base_url
        self.token = token
        self.txn_id = 0

    def initial_sync(self, limit=1):
        return self._send("GET", "/initialSync", query_params={"limit": limit})

    def register(self, login_type, **kwargs):
        content = {
            "type": login_type
        }
        for key in kwargs:
            content[key] = kwargs[key]

        return self._send("POST", "/register", content)

    def login(self, login_type, **kwargs):
        content = {
            "type": login_type
        }
        for key in kwargs:
            content[key] = kwargs[key]

        return self._send("POST", "/login", content)

    def create_room(self, alias=None, is_public=False, invitees=()):
        content = {
            "visibility": "public" if is_public else "private"
        }
        if alias:
            content["room_alias_name"] = alias
        if invitees:
            content["invite"] = invitees
        return self._send("POST", "/createRoom", content)

    def join_room(self, alias=None, room_id=None):
        if not alias and not room_id:
            raise MatrixError("No alias or room ID to join.")

        path = "/join/"
        if alias:
            path += alias
        elif room_id:
            path += room_id

        return self._send("POST", path)

    def event_stream(self, from_token, timeout=30000):
        path = "/events"
        return self._send(
            "GET", path, query_params={
                "timeout": timeout,
                "from": from_token
            }
        )

    def send_state_event(self, room_id, event_type, content, state_key=""):
        path = ("/rooms/%s/state/%s" %
            (urllib.quote(room_id), urllib.quote(event_type))
        )
        if state_key:
            path += "/%s" % (urllib.quote(state_key))
        return self._send("PUT", path, content)

    def send_message_event(self, room_id, event_type, content, txn_id=None):
        if not txn_id:
            txn_id = self.txn_id

        self.txn_id = self.txn_id + 1

        path = ("/rooms/%s/send/%s/%s" %
            (urllib.quote(room_id), urllib.quote(event_type),
             urllib.quote(unicode(txn_id)))
        )
        return self._send("PUT", path, content)

    def send_message(self, room_id, text_content):
        return self.send_message_event(
            room_id, "m.room.message",
            self.get_text_body(text_content)
        )

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
        )

        if response.status_code < 200 or response.status_code >= 300:
            raise MatrixRequestError(
                code=response.status_code, content=response.text
            )

        return response.json()
