import re
from uuid import uuid4

from .room import Room
from .user import User
from .errors import MatrixRequestError


class Group(object):
    """ The Group class can be used to call group specific functions.

        WARNING: This class uses the unstable groups API. Therefore, it might
        be broken or break at any time.
    """

    def __init__(self, client, group_id):
        """ Create a blank Group object.

            NOTE: This should ideally be called from within the Client.
            NOTE: This does not verify the group with the Home Server.
        """
        if not group_id.startswith("+"):
            raise ValueError("Group IDs start with +")

        if ":" not in group_id:
            raise ValueError("Group IDs must have a domain component, seperated by a :")

        self.group_id = group_id
        self.client = client

    def get_members(self):
        """Query joined members of this group.

        WARNING: For now, every call to this method causes a request to be
        made, hitting the server API. This will change once the groups API has
        stabilized and events are received via the sync method. For now, please
        take care not to overuse this method.

        WARNING: This method uses the unstable groups API. Therefore, it might
        be broken or break at any time.

        Returns:
            [ user_id ]: List of user IDs of the users in the group.
        """
        response = self.client.api.get_users_in_group(self.group_id)
        return [event["user_id"] for event in response["chunk"]]

    def get_invited_users(self):
        """Query users invited to this group.

        WARNING: For now, every call to this method causes a request to be
        made, hitting the server API. This will change once the groups API has
        stabilized and events are received via the sync method. For now, please
        take care not to overuse this method.

        WARNING: This method uses the unstable groups API. Therefore, it might
        be broken or break at any time.

        Returns:
            [ user_id ]: List of user IDs of the users invited to this the group.
        """
        response = self.client.api.get_invited_users_in_group(self.group_id)
        return [event["user_id"] for event in response["chunk"]]

    def invite_user(self, user_id):
        """Invite a user to this group.

        WARNING: This method uses the unstable groups API. Therefore, it might
        be broken or break at any time.

        Args:
            user_id (str): The user ID of a user to be invited.

        Returns:
            boolean: The invitation was sent.
        """
        try:
            self.client.api.invite_user_to_group(self.group_id, user_id)
            return True
        except MatrixRequestError:
            return False

    def kick_user(self, user_id):
        """Kick a user from this group.

        WARNING: This method uses the unstable groups API. Therefore, it might
        be broken or break at any time.

        Args:
            user_id (str): The user ID of the user to be kicked.

        Returns:
            boolean: The user was kicked.
        """
        try:
            self.client.api.kick_user_from_group(self.group_id, user_id)
            return True
        except MatrixRequestError:
            return False

    def add_room(self, room_id):
        """Add a room to the group.

        WARNING: This method uses the unstable groups API. Therefore, it might
        be broken or break at any time.

        Args:
            room_id (str): The room ID of the room to be added.

        Returns:
            boolean: True if the room was added.
        """
        if isinstance(room_id, Room):
            room_id = room_id.room_id

        try:
            self.client.api.add_room_to_group(self.group_id, room_id)
            return True
        except MatrixRequestError:
            return False

    def remove_room(self, room_id):
        """Remove a room from the group.

        WARNING: This method uses the unstable groups API. Therefore, it might
        be broken or break at any time.

        Args:
            room_id (str): The room ID of the room to be removed.

        Returns:
            boolean: True if the room was removed.
        """
        if isinstance(room_id, Room):
            room_id = room_id.room_id

        try:
            self.client.api.remove_room_from_group(self.group_id, room_id)
            return True
        except MatrixRequestError:
            return False

    def get_rooms(self):
        """Get the rooms associated with this group.

        WARNING: For now, every call to this method causes a request to be
        made, hitting the server API. This will change once the groups API has
        stabilized and events are received via the sync method. For now, please
        take care not to overuse this method.

        WARNING: This method uses the unstable groups API. Therefore, it might
        be broken or break at any time.

        Returns:
            [ room_id ]: List of room IDs of the rooms in the group.
        """
        response = self.client.api.get_rooms_in_group(self.group_id)
        return [event["room_id"] for event in response["chunk"]]

    @property
    def name(self):
        """Gets the room's name.

        WARNING: For now, every call to this method causes a request to be
        made, hitting the server API. This will change once the groups API has
        stabilized and events are received via the sync method. For now, please
        take care not to overuse this method.

        WARNING: This method uses the unstable groups API. Therefore, it might
        be broken or break at any time.

        Returns
            str: The name of the group.
        """
        return self.client.api.get_group_profile(self.group_id)["name"]

    @property
    def short_description(self):
        """Gets the room's short description.

        WARNING: For now, every call to this method causes a request to be
        made, hitting the server API. This will change once the groups API has
        stabilized and events are received via the sync method. For now, please
        take care not to overuse this method.

        WARNING: This method uses the unstable groups API. Therefore, it might
        be broken or break at any time.

        Returns
            str: The short description of the group.
        """
        return self.client.api.get_group_profile(self.group_id)["short_description"]

    @property
    def long_description(self):
        """Gets the room's long description.

        WARNING: For now, every call to this method causes a request to be
        made, hitting the server API. This will change once the groups API has
        stabilized and events are received via the sync method. For now, please
        take care not to overuse this method.

        WARNING: This method uses the unstable groups API. Therefore, it might
        be broken or break at any time.

        Returns
            str: The long description of the group.
        """
        return self.client.api.get_group_profile(self.group_id)["long_description"]

    @property
    def avatar_url(self):
        """Gets the room's avatar URL.

        WARNING: For now, every call to this method causes a request to be
        made, hitting the server API. This will change once the groups API has
        stabilized and events are received via the sync method. For now, please
        take care not to overuse this method.

        WARNING: This method uses the unstable groups API. Therefore, it might
        be broken or break at any time.

        Returns
            str: The avatar URL of the group.
        """
        return self.client.api.get_group_profile(self.group_id)["avatar_url"]
