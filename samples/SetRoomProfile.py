#!/usr/bin/env python3

# Set a profile for a room.
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
    client.login(username, password, sync=False)
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

room = client.join_room(input("Room:"))
displayname = input("Displayname:")
if len(displayname) == 0:
    print("Not setting displayname")
    displayname = None

avatar = input("Avatar:")
if len(avatar) == 0:
    print("Not setting avatar")
    avatar = None

try:
    room.set_user_profile(displayname, avatar)
except MatrixRequestError as e:
    print(e)
    sys.exit(11)
