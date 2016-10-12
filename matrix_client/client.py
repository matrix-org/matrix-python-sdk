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
from .api import MatrixHttpApi, MatrixRequestError, MatrixUnexpectedResponse
from threading import Thread
from time import sleep
import logging
import sys

logger = logging.getLogger(__name__)


class MatrixClient(object):
    """
    The client API for Matrix. For the raw HTTP calls, see MatrixHttpApi.

    Usage (new user):
        client = MatrixClient("https://matrix.org")
        token = client.register_with_password(username="foobar",
            password="monkey")
        room = client.create_room("myroom")
        room.send_image(file_like_object)

    Usage (logged in):
        client = MatrixClient("https://matrix.org", token="foobar",
            user_id="@foobar:matrix.org")
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

    def __init__(self, base_url, token=None, user_id=None, valid_cert_check=True):
        """ Create a new Matrix Client object.

        Args:
            base_url (str): The url of the HS preceding /_matrix.
                e.g. (ex: https://localhost:8008 )
            token (Optional[str]): If you have an access token
                supply it here.
            user_id (Optional[str]): You must supply the user_id
                (as obtained when initially logging in to obtain
                the token) if supplying a token; otherwise, ignored.
            valid_cert_check (bool): Check the homeservers
                certificate on connections?

        Returns:
            MatrixClient

        Raises:
            MatrixRequestError, ValueError
        """
        if token is not None and user_id is None:
            raise ValueError("must supply user_id along with token")

        self.api = MatrixHttpApi(base_url, token)
        self.api.validate_certificate(valid_cert_check)
        self.listeners = []
        self.invite_listeners = []
        self.left_listeners = []

        self.sync_token = None
        self.sync_filter = None

        """ Time to wait before attempting a /sync request after failing."""
        self.bad_sync_timeout_limit = 60 * 60
        self.rooms = {
            # room_id: Room
        }
        if token:
            self.user_id = user_id
            self._sync()

    def get_sync_token(self):
        return self.sync_token

    def set_sync_token(self, token):
        self.sync_token = token

    def register_with_password(self, username, password, limit=1):
        """ Register for a new account on this HS.

        Args:
            username (str): Account username
            password (str): Account password
            limit (int): Deprecated. How many messages to return when syncing.

        Returns:
            str: Access Token

        Raises:
            MatrixRequestError
        """
        response = self.api.register(
            "m.login.password", user=username, password=password
        )
        self.user_id = response["user_id"]
        self.token = response["access_token"]
        self.hs = response["home_server"]
        self.api.token = self.token
        self._sync()
        return self.token

    def login_with_password(self, username, password, limit=10):
        """ Login to the homeserver.

        Args:
            username (str): Account username
            password (str): Account password
            limit (int): Deprecated. How many messages to return when syncing.
                This will be replaced by a filter API in a later release.

        Returns:
            str: Access token

        Raises:
            MatrixRequestError
        """
        response = self.api.login(
            "m.login.password", user=username, password=password
        )
        self.user_id = response["user_id"]
        self.token = response["access_token"]
        self.hs = response["home_server"]
        self.api.token = self.token

        """ Limit Filter """
        self.sync_filter = '{ "room": { "timeline" : { "limit" : %i } } }' % limit
        self._sync()
        return self.token

    def create_room(self, alias=None, is_public=False, invitees=()):
        """ Create a new room on the homeserver.

        Args:
            alias (str): The canonical_alias of the room.
            is_public (bool):  The public/private visibility of the room.
            invitees (str[]): A set of user ids to invite into the room.

        Returns:
            Room

        Raises:
            MatrixRequestError
        """
        response = self.api.create_room(alias, is_public, invitees)
        return self._mkroom(response["room_id"])

    def join_room(self, room_id_or_alias):
        """ Join a room.

        Args:
            room_id_or_alias (str): Room ID or an alias.

        Returns:
            Room

        Raises:
            MatrixRequestError
        """
        response = self.api.join_room(room_id_or_alias)
        room_id = (
            response["room_id"] if "room_id" in response else room_id_or_alias
        )
        return self._mkroom(room_id)

    def get_rooms(self):
        """ Return a list of Room objects that the user has joined.

        Returns:
            Room[]: Rooms the user has joined.

        """
        return self.rooms

    def add_listener(self, callback, event_type=None):
        """ Add a listener that will send a callback when the client recieves
        an event.

        Args:
            callback (func(roomchunk)): Callback called when an event arrives.
            event_type (str): The event_type to filter for.
        """
        self.listeners.append(
            {
                'callback': callback,
                'event_type': event_type
            }
        )

    def add_invite_listener(self, callback):
        """ Add a listener that will send a callback when the client receives
        an invite.

        Args:
            callback (func(room_id, state)): Callback called when an invite arrives.
        """
        self.invite_listeners.append(callback)

    def add_leave_listener(self, callback):
        """ Add a listener that will send a callback when the client has left a room.
        an invite request.

        Args:
            callback (func(room_id, room)): Callback called when the client
            has left a room.
        """
        self.left_listeners.append(callback)

    def listen_for_events(self, timeout_ms=30000):
        """Deprecated. sync now pulls events from the request.
        This function just calls _sync()

        Args:
            timeout_ms (int): How long to poll the Home Server for before
               retrying.
        """
        self._sync(timeout_ms)

    def listen_forever(self, timeout_ms=30000):
        """ Keep listening for events forever.

        Args:
            timeout_ms (int): How long to poll the Home Server for before
               retrying.
        """
        bad_sync_timeout = 5000
        while(True):
            try:
                self._sync(timeout_ms)
                bad_sync_timeout = 5
            except MatrixRequestError as e:
                logger.warning("A MatrixRequestError occured during sync.")
                if e.code >= 500:
                    logger.warning("Problem occured serverside. Waiting %i seconds",
                                   bad_sync_timeout)
                    sleep(bad_sync_timeout)
                    bad_sync_timeout = min(bad_sync_timeout * 2,
                                           self.bad_sync_timeout_limit)
                else:
                    raise e
            except Exception as e:
                logger.exception("Exception thrown during sync")

    def start_listener_thread(self, timeout_ms=30000):
        """ Start a listener thread to listen for events in the background.

        Args:
            timeout (int): How long to poll the Home Server for before
               retrying.
        """
        try:
            thread = Thread(target=self.listen_forever, args=(timeout_ms, ))
            thread.daemon = True
            thread.start()
        except:
            e = sys.exc_info()[0]
            logger.error("Error: unable to start thread. %s", str(e))

    def upload(self, content, content_type):
        """ Upload content to the home server and recieve a MXC url.

        Args:
            content (bytes): The data of the content.
            content_type (str): The mimetype of the content.

        Raises:
            MatrixUnexpectedResponse: If the homeserver gave a strange response
            MatrixRequestError: If the upload failed for some reason.
        """
        try:
            response = self.api.media_upload(content, content_type)
            if "content_uri" in response:
                return response["content_uri"]
            else:
                raise MatrixUnexpectedResponse(
                    "The upload was successful, but content_uri wasn't found."
                )
        except MatrixRequestError as e:
            raise MatrixRequestError(
                code=e.code,
                content="Upload failed: %s" % e
            )

    def _mkroom(self, room_id):
        self.rooms[room_id] = Room(self, room_id)
        return self.rooms[room_id]

    def _process_state_event(self, state_event, current_room):
        if "type" not in state_event:
            return  # Ignore event
        etype = state_event["type"]

        if etype == "m.room.name":
            current_room.name = state_event["content"].get("name", None)
        elif etype == "m.room.topic":
            current_room.topic = state_event["content"].get("topic", None)
        elif etype == "m.room.aliases":
            current_room.aliases = state_event["content"].get("aliases", None)

        for listener in current_room.state_listeners:
            if (
                listener['event_type'] is None or
                listener['event_type'] == state_event['type']
            ):
                listener['callback'](state_event)

    def _sync(self, timeout_ms=30000):
        # TODO: Deal with presence
        # TODO: Deal with left rooms
        response = self.api.sync(self.sync_token, timeout_ms, filter=self.sync_filter)
        self.sync_token = response["next_batch"]

        for room_id, invite_room in response['rooms']['invite'].items():
            for listener in self.invite_listeners:
                listener(room_id, invite_room['invite_state'])

        for room_id, left_room in response['rooms']['leave'].items():
            for listener in self.left_listeners:
                listener(room_id, left_room)

        for room_id, sync_room in response['rooms']['join'].items():
            if room_id not in self.rooms:
                self._mkroom(room_id)
            room = self.rooms[room_id]

            for event in sync_room["state"]["events"]:
                self._process_state_event(event, room)

            for event in sync_room["timeline"]["events"]:
                room._put_event(event)

                # Dispatch for client (global) listeners
                for listener in self.listeners:
                    if (
                        listener['event_type'] is None or
                        listener['event_type'] == event['type']
                    ):
                        listener['callback'](event)

    def get_user(self, user_id):
        """ Return a User by their id.

        NOTE: This function only returns a user object, it does not verify
            the user with the Home Server.

        Args:
            user_id (str): The matrix user id of a user.
        """

        return User(self.api, user_id)


class Room(object):
    """ The Room class can be used to call room specific functions
    after joining a room from the Client.
    """

    def __init__(self, client, room_id):
        """ Create a blank Room object.

            NOTE: This should ideally be called from within the Client.
            NOTE: This does not verify the room with the Home Server.
        """
        if not room_id.startswith("!"):
            raise ValueError("RoomIDs start with !")

        if ":" not in room_id:
            raise ValueError("RoomIDs must have a domain component, seperated by a :")

        self.room_id = room_id
        self.client = client
        self.listeners = []
        self.state_listeners = []
        self.events = []
        self.event_history_limit = 20
        self.name = None
        self.aliases = []
        self.topic = None

    def send_text(self, text):
        """ Send a plain text message to the room.

        Args:
            text (str): The message to send
        """
        return self.client.api.send_message(self.room_id, text)

    def send_emote(self, text):
        """ Send a emote (/me style) message to the room.

        Args:
            text (str): The message to send
        """
        return self.client.api.send_emote(self.room_id, text)

    def send_notice(self, text):
        return self.client.api.send_notice(self.room_id, text)

    # See http://matrix.org/docs/spec/r0.0.1/client_server.html#m-image for the
    # imageinfo args.
    def send_image(self, url, name, **imageinfo):
        """ Send a pre-uploaded image to the room.
        See http://matrix.org/docs/spec/r0.0.1/client_server.html#m-image
        for imageinfo

        Args:
            url (str): The mxc url of the image.
            name (str): The filename of the image.
            imageinfo (): Extra information about the image.
        """
        return self.client.api.send_content(
            self.room_id, url, name, "m.image",
            extra_information=imageinfo
        )

    def add_listener(self, callback, event_type=None):
        """ Add a callback handler for events going to this room.

        Args:
            callback (func(roomchunk)): Callback called when an event arrives.
            event_type (str): The event_type to filter for.
        """
        self.listeners.append(
            {
                'callback': callback,
                'event_type': event_type
            }
        )

    def add_state_listener(self, callback, event_type=None):
        """ Add a callback handler for state events going to this room.

        Args:
            callback (func(roomchunk)): Callback called when an event arrives.
            event_type (str): The event_type to filter for.
        """
        self.state_listeners.append(
            {
                'callback': callback,
                'event_type': event_type
            }
        )

    def _put_event(self, event):
        self.events.append(event)
        if len(self.events) > self.event_history_limit:
            self.events.pop(0)

        # Dispatch for room-specific listeners
        for listener in self.listeners:
            if listener['event_type'] is None or listener['event_type'] == event['type']:
                listener['callback'](self, event)

        # Dispatch for client (global) listeners
        for listener in self.client.listeners:
            listener(self, event)

    def get_events(self):
        """ Get the most recent events for this room.

        Returns:
            events
        """
        return self.events

    def invite_user(self, user_id):
        """ Invite a user to this room

        Args:
            user_id (str): The matrix user id of a user.

        Returns:
            boolean: The invitation was sent.
        """
        try:
            self.client.api.invite_user(self.room_id, user_id)
            return True
        except MatrixRequestError:
            return False

    def kick_user(self, user_id, reason=""):
        """ Kick a user from this room

        Args:
            user_id (str): The matrix user id of a user.

        Returns:
            boolean: The user was kicked.
        """
        try:
            self.client.api.kick_user(self.room_id, user_id)
            return True
        except MatrixRequestError:
            return False

    def ban_user(self, user_id, reason):
        """ Ban a user from this room

        Args:
            user_id (str): The matrix user id of a user.
            reason  (str): A reason for banning the user.

        Returns:
            boolean: The user was banned.
        """
        try:
            self.client.api.ban_user(self.room_id, user_id, reason)
            return True
        except MatrixRequestError:
            return False

    def leave(self):
        """ Leave the room.

        Returns:
            boolean: Leaving the room was successful.
        """
        try:
            self.client.api.leave_room(self.room_id)
            self.client.rooms.remove(self.room_id)
            return True
        except MatrixRequestError:
            return False

    def update_room_name(self):
        """ Get room name

        Returns:
            boolean: True if the room name changed, False if not
        """
        try:
            response = self.client.api.get_room_name(self.room_id)
            if "name" in response and response["name"] != self.name:
                self.name = response["name"]
                return True
            else:
                return False
        except MatrixRequestError:
            return False

    def send_state_event(self, event_type, content, state_key):
        """ Send a state event to the room.

        Args:
            event_type (str): The type of event that you are sending.
            content (): An object with the content of the message.
            state_key (str, optional): A unique key to identify the state.
        """
        return self.client.api.send_state_event(
            self.room_id,
            event_type,
            content,
            state_key
        )

    def update_room_topic(self):
        """ Get room topic

        Returns:
            boolean: True if the topic changed, False if not
        """
        try:
            response = self.client.api.get_room_topic(self.room_id)
            if "topic" in response and response["topic"] != self.topic:
                self.topic = response["topic"]
                return True
            else:
                return False
        except MatrixRequestError:
            return False

    def update_aliases(self):
        """ Get aliases information from room state

        Returns:
            boolean: True if the aliases changed, False if not
        """
        try:
            response = self.client.api.get_room_state(self.room_id)
            for chunk in response:
                if "content" in chunk and "aliases" in chunk["content"]:
                    if chunk["content"]["aliases"] != self.aliases:
                        self.aliases = chunk["content"]["aliases"]
                        return True
                    else:
                        return False
        except MatrixRequestError:
            return False


class User(object):
    """ The User class can be used to call user specific functions.
    """
    def __init__(self, api, user_id):
        if not user_id.startswith("@"):
            raise ValueError("UserIDs start with @")

        if ":" not in user_id:
            raise ValueError("UserIDs must have a domain component, seperated by a :")

        self.user_id = user_id
        self.api = api

    def get_display_name(self):
        """ Get this users display name.
            See also get_friendly_name()

        Returns:
            str: Display Name
        """
        return self.api.get_display_name(self.user_id)

    def get_friendly_name(self):
        display_name = self.api.get_display_name(self.user_id)
        return display_name if display_name is not None else self.user_id

    def set_display_name(self, display_name):
        """ Set this users display name.

        Args:
            display_name (str): Display Name
        """
        return self.api.set_display_name(self.user_id, display_name)

    def get_avatar_url(self):
        mxcurl = self.api.get_avatar_url(self.user_id)
        url = self.api.get_download_url(mxcurl)
        return url

    def set_avatar_url(self, avatar_url):
        """ Set this users avatar.

        Args:
            avatar_url (str): mxc url from previously uploaded
        """
        return self.api.set_avatar_url(self.user_id, avatar_url)
