import re
from uuid import uuid4

from .errors import MatrixRequestError


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
        self.ephemeral_listeners = []
        self.events = []
        self.event_history_limit = 20
        self.name = None
        self.aliases = []
        self.topic = None
        self._prev_batch = None

    def set_user_profile(self,
                         displayname=None,
                         avatar_url=None,
                         reason="Changing room profile information"):
        member = self.client.api.get_membership(self.room_id, self.client.user_id)
        if member["membership"] != "join":
            raise Exception("Can't set profile if you have not joined the room.")
        if displayname is None:
            displayname = member["displayname"]
        if avatar_url is None:
            avatar_url = member["avatar_url"]
        self.client.api.set_membership(
            self.room_id,
            self.client.user_id,
            'join',
            reason, {
                "displayname": displayname,
                "avatar_url": avatar_url
            }
        )

    def send_text(self, text):
        """ Send a plain text message to the room.

        Args:
            text (str): The message to send
        """
        return self.client.api.send_message(self.room_id, text)

    def get_html_content(self, html, body=None, msgtype="m.text"):
        return {
            "body": body if body else re.sub('<[^<]+?>', '', html),
            "msgtype": msgtype,
            "format": "org.matrix.custom.html",
            "formatted_body": html
        }

    def send_html(self, html, body=None, msgtype="m.text"):
        """Send an html formatted message.

        Args:
            html (str): The html formatted message to be sent.
            body (str): The body of the message to be sent (unformatted).
        """
        return self.client.api.send_message_event(
            self.room_id, "m.room.message", self.get_html_content(html, body, msgtype))

    def set_account_data(self, type, account_data):
        return self.client.api.set_room_account_data(
            self.client.user_id, self.room_id, type, account_data)

    def get_tags(self):
        return self.client.api.get_user_tags(self.client.user_id, self.room_id)

    def remove_tag(self, tag):
        return self.client.api.remove_user_tag(
            self.client.user_id, self.room_id, tag
        )

    def add_tag(self, tag, order=None, content=None):
        return self.client.api.add_user_tag(
            self.client.user_id, self.room_id,
            tag, order, content
        )

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

    def send_location(self, geo_uri, name, thumb_url=None, **thumb_info):
        """ Send a location to the room.
        See http://matrix.org/docs/spec/client_server/r0.2.0.html#m-location
        for thumb_info

        Args:
            geo_uri (str): The geo uri representing the location.
            name (str): Description for the location.
            thumb_url (str): URL to the thumbnail of the location.
            thumb_info (): Metadata about the thumbnail, type ImageInfo.
        """
        return self.client.api.send_location(self.room_id, geo_uri, name,
                                             thumb_url, thumb_info)

    # See http://matrix.org/docs/spec/client_server/r0.2.0.html#m-video for the
    # videoinfo args.
    def send_video(self, url, name, **videoinfo):
        """ Send a pre-uploaded video to the room.
        See http://matrix.org/docs/spec/client_server/r0.2.0.html#m-video
        for videoinfo

        Args:
            url (str): The mxc url of the video.
            name (str): The filename of the video.
            videoinfo (): Extra information about the video.
        """
        return self.client.api.send_content(self.room_id, url, name, "m.video",
                                            extra_information=videoinfo)

    # See http://matrix.org/docs/spec/client_server/r0.2.0.html#m-audio for the
    # audioinfo args.
    def send_audio(self, url, name, **audioinfo):
        """ Send a pre-uploaded audio to the room.
        See http://matrix.org/docs/spec/client_server/r0.2.0.html#m-audio
        for audioinfo

        Args:
            url (str): The mxc url of the audio.
            name (str): The filename of the audio.
            audioinfo (): Extra information about the audio.
        """
        return self.client.api.send_content(self.room_id, url, name, "m.audio",
                                            extra_information=audioinfo)

    def add_listener(self, callback, event_type=None):
        """ Add a callback handler for events going to this room.

        Args:
            callback (func(room, event)): Callback called when an event arrives.
            event_type (str): The event_type to filter for.
        Returns:
            uuid.UUID: Unique id of the listener, can be used to identify the listener.
        """
        listener_id = uuid4()
        self.listeners.append(
            {
                'uid': listener_id,
                'callback': callback,
                'event_type': event_type
            }
        )
        return listener_id

    def remove_listener(self, uid):
        """ Remove listener with given uid.

        Args:
            uuid.UUID: Unique id of the listener to remove.
        """
        self.listeners[:] = (listener for listener in self.listeners
                             if listener['uid'] != uid)

    def add_ephemeral_listener(self, callback, event_type=None):
        """ Add a callback handler for ephemeral events going to this room.

        Args:
            callback (func(room, event)): Callback called when an ephemeral event arrives.
            event_type (str): The event_type to filter for.
        Returns:
            uuid.UUID: Unique id of the listener, can be used to identify the listener.
        """
        listener_id = uuid4()
        self.ephemeral_listeners.append(
            {
                'uid': listener_id,
                'callback': callback,
                'event_type': event_type
            }
        )
        return listener_id

    def remove_ephemeral_listener(self, uid):
        """ Remove ephemeral listener with given uid.

        Args:
            uuid.UUID: Unique id of the listener to remove.
        """
        self.ephemeral_listeners[:] = (listener for listener in self.ephemeral_listeners
                                       if listener['uid'] != uid)

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

    def _put_ephemeral_event(self, event):
        # Dispatch for room-specific listeners
        for listener in self.ephemeral_listeners:
            if listener['event_type'] is None or listener['event_type'] == event['type']:
                listener['callback'](self, event)

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

    def unban_user(self, user_id):
        """Unban a user from this room

        Args:
            user_id (str): The matrix user id of a user.

        Returns:
            boolean: The user was unbanned.
        """
        try:
            self.client.api.unban_user(self.room_id, user_id)
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
            del self.client.rooms[self.room_id]
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

    def set_room_name(self, name):
        """ Set room name
            name (str): The new name for the room

        Returns:
            boolean: True if the name changed, False if not
        """
        try:
            self.client.api.set_room_name(self.room_id, name)
            self.name = name
            return True
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

    def set_room_topic(self, topic):
        """ Set room topic
            topic (str): The new topic for the room

        Returns:
            boolean: True if the topic changed, False if not
        """
        try:
            self.client.api.set_room_topic(self.room_id, topic)
            self.topic = topic
            return True
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

    def add_room_alias(self, room_alias):
        """Add an alias to the room

        Args:
            room_alias(str): Room wanted alias name.

        Returns:
            bool: True if the alias was added, False otherwise.
        """
        try:
            self.client.api.set_room_alias(self.room_id, room_alias)
            return True
        except MatrixRequestError:
            return False

    def get_joined_members(self):
        """Query joined members of this room.

        Returns:
            {user_id: {"displayname": str or None}}: Dictionary of joined members.
        """
        response = self.client.api.get_room_members(self.room_id)
        rtn = {
            event["state_key"]: {
                "displayname": event["content"].get("displayname"),
            } for event in response["chunk"] if event["content"]["membership"] == "join"
        }

        return rtn

    def backfill_previous_messages(self, reverse=False, limit=10):
        """Backfill handling of previous messages.

        Args:
            reverse (bool): When false messages will be backfilled in their original
                order (old to new), otherwise the order will be reversed (new to old).
            limit (int): Number of messages to go back.
        """
        res = self.client.api.get_room_messages(self.room_id, self.prev_batch,
                                                direction="b", limit=limit)
        events = res["chunk"]
        if not reverse:
            events = reversed(events)
        for event in events:
            self._put_event(event)

    @property
    def prev_batch(self):
        return self._prev_batch

    @prev_batch.setter
    def prev_batch(self, prev_batch):
        self._prev_batch = prev_batch
