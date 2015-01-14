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
from .api import MatrixHttpApi

# TODO: Finish implementing this.


class MatrixClient(object):
    """ WORK IN PROGRESS
    The client API for Matrix. For the raw HTTP calls, see MatrixHttpApi.

    Usage (new user):
        client = MatrixClient("https://matrix.org")
        token = client.register_with_password(username="foobar", password="monkey")
        room = client.create_room("myroom")
        room.send_image(file_like_object)

    Usage (logged in):
        client = MatrixClient("https://matrix.org", token="foobar")
        rooms = client.get_rooms()  # NB: From initial sync
        client.add_listener(func)  # NB: event stream callback
        rooms[0].add_listener(func)  # NB: callbacks just for this room.
        room = client.join_room("#matrix:matrix.org")
        response = room.send_text("Hello!")
        response = room.kick("@bob:matrix.org")

    Incoming event callbacks (scopes):

        def user_callback(user, incoming_event):
            pass

        def room_callback(room, incoming_event):
            pass

        def global_callback(incoming_event):
            pass

    """

    def __init__(self, base_url, token=None):
        self.api = MatrixHttpApi(base_url, token)
        self.listeners = []
        self.rooms = {
            # room_id: Room
        }
        if token:
            self._sync()

    def register_with_password(self, username, password):
        response = self.api.register(
            "m.login.password", user=username, password=password
        )
        self.user_id = response["user_id"]
        self.token = response["access_token"]
        self.hs = response["home_server"]
        self.api.token = self.token
        self._sync()
        return self.token

    def login_with_password(self, username, password):
        response = self.api.login(
            "m.login.password", user=username, password=password
        )
        self.user_id = response["user_id"]
        self.token = response["access_token"]
        self.hs = response["home_server"]
        self.api.token = self.token
        self._sync()
        return self.token

    def create_room(self, alias=None, is_public=False, invitees=()):
        response = self.api.create_room(alias, is_public, invitees)
        return self._mkroom(response["room_id"])

    def join_room(self, room_id_or_alias):
        response = self.api.join_room(room_id_or_alias)
        room_id = (
            response["room_id"] if "room_id" in response else room_id_or_alias
        )
        return self._mkroom(room_id)

    def get_rooms(self):
        return self.rooms

    def add_listener(self, callback):
        self.listeners.append(callback)

    def listen_for_events(self, timeout=30000):
        event = self.api.event_stream(self.end, timeout)
        self.end = event["end"]
        for listener in self.listeners:
            listener(event)
        for chunk in event["chunk"]:
            if "room_id" in chunk:
                for listener in self.rooms[chunk["room_id"]].listeners:
                    listener(
                        {
                            "chunk": [chunk],
                            "start": event["start"],
                            "end": event["end"]
                        })


    def _mkroom(self, room_id):
        self.rooms[room_id] = Room(self, room_id)
        return self.rooms[room_id]

    def _sync(self):
        response = self.api.initial_sync()
        try:
            for room in response["rooms"]:
                self._mkroom(room["room_id"])
            self.end = response["end"]
        except KeyError:
            pass


class Room(object):

    def __init__(self, client, room_id):
        self.room_id = room_id
        self.client = client
        self.listeners = []

    def send_text(self, text):
        return self.client.api.send_message(self.room_id, text)

    def add_listener(self, callback):
        self.listeners.append(callback)
