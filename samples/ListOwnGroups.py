#!/usr/bin/env python3

# List the groups we are in, including their users.
# Args: host:port username password
# Error Codes:
# 2 - Could not find the server.
# 3 - Bad URL Format.
# 4 - Bad username/password.
# 11 - Serverside Error

import sys
import samples_common

from matrix_client.client import MatrixClient
from matrix_client.api import MatrixRequestError
from requests.exceptions import MissingSchema


host, username, password = samples_common.get_user_details(sys.argv)

client = MatrixClient(host)

try:
    client.login_with_password_no_sync(username, password)
except MatrixRequestError as e:
    print(e)
    if e.code == 403:
        print("Bad username or password.")
        sys.exit(4)
    else:
        print("Check your server details are correct.")
        sys.exit(2)
except MissingSchema as e:
    print("Bad URL format.")
    print(e)
    sys.exit(3)

groups = client.get_groups()
if len(groups) == 0:
    print("No groups joined")

for group_id, group in groups.items():
    print("=== Group: {}".format(group_id))

    print("Name: {}".format(group.name))
    print("Short Description: {}".format(group.short_description))
    print("Long Description: {}".format(group.long_description))
    print("Avatar URL: {}".format(group.avatar_url))

    print("Members: ")
    for user_id in group.get_members():
        print(" * {}".format(user_id))

    print("Invited Users: ")
    for user_id in group.get_invited_users():
        print(" * {}".format(user_id))

    print("Rooms: ")
    for room_id in group.get_rooms():
        print(" * {}".format(room_id))
