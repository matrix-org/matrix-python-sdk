# -*- coding: utf-8 -*-
from matrix_client.api import MatrixHttpApi
try:
    basestring
except NameError:
    basestring = str


class MatrixHttpAdminApi(MatrixHttpApi):
    """Extends Matrix API with admin calls.

    Examples:
        Create a client and send a message::

            matrix = MatrixHttpAdminApi("https://matrix.org", token="foobar")
            response = admin_api.shutdown_room(
                "!DgvjtOljKujDBrxyHk:matrix.org",
                "@admin:matrix.org",
                room_name="New room",
                message="Old room closed by admin"
            )
    """
    def purge_history(self, room_id, event_id):
        """Perform /admin/purge_hostory.
        Admin api part.
        Args:
            room_id (str): Room_id to purge.
            event_id (str or int): Event_id or ts to purge before.
        """
        if isinstance(event_id, basestring):
            content = {
                "delete_local_events": True,
                "purge_up_to_event_id": event_id
            }
        else:
            content = {
                "delete_local_events": True,
                "purge_up_to_ts": int(event_id)
            }
        return self._send("POST", "/admin/purge_history/%s" % room_id, content)

    def purge_history_status(self, purge_id):
        """Perform /admin/purge_history_status.
        Admin api part.
        Args:
            purge_id (str): Purge_id to query status.
        """
        return self._send("GET", "/admin/purge_history_status/%s" % purge_id)

    def media_in_room(self, room_id, event_id=None):
        """List remote and local media in room.
        Args:
            room_id (str): Room_id to purge.
        """
        return self._send("GET", "/admin/room/%s/media" % room_id)

    def whois(self, user_id):
        """Query server for user information (ip, UA, last seen).
        Admin api part.
        Args:
            user_id (str): user_id to query.
        """
        return self._send("GET", "/admin/whois/%s" % user_id)

    def deactivate(self, user_id, erase=False):
        """Deactivate user account.
        Admin api part.
        Args:
            user_id (str): user_id to deactivate.
            erase (bool): erase user data. Default no.
        """
        content = {
            "erase": erase
        }
        return self._send("POST", "/admin/deactivate/%s" % user_id, content)

    def reset_password(self, user_id, password):
        """Reset users's password to provided.
        Admin api part.
        Args:
            user_id (str): user_id to deactivate.
            password (str): password to set.
        """
        content = {
            "new_password": password
        }
        return self._send("POST", "/admin/reset_password/%s" % user_id, content)

    def quarantine_media(self, room_id):
        """Quarantine all media in room so that no one can download it via thi server.
        Admin api part.
        Args:
            room_id (str): room_id to quarantine.
        """
        return self._send("POST", "/admin/quarantine_media/%s" % room_id)

    def shutdown_room(self, room_id, new_room_user_id, room_name=False, message=False):
        """Shuts down a room by removing all local users from the room and blocking
        all future invites and joins to the room. Any local aliases will be repointed
        to a new room created by `new_room_user_id` and kicked users will be auto
        joined to the new room
        Admin api part.
        Args:
            room_id (str): room_id to quarantine.
            new_room_user_id (str): new room creator user_id.
            room_name (str): new room name.
            message (str): information message for new room.
        """
        content = {
            "new_room_user_id": new_room_user_id
        }
        if room_name:
            content["room_name"] = room_name
        if message:
            content["message"] = message
        return self._send("POST", "/admin/shutdown_room/%s" % room_id, content)
