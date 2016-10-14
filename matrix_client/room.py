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
