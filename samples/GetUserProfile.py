#!/usr/bin/env python3

# Get a users display name and avatar
# Args: host:port username password user_id
# Error Codes:
# 2 - Could not find the server.
# 3 - Bad URL Format.
# 4 - Bad username/password.


import sys
import samples_common  # Common bits used between samples

from matrix_client.client import MatrixClient
from matrix_client.api import MatrixRequestError
from requests.exceptions import MissingSchema

host, username, password = samples_common.get_user_details(sys.argv)

client = MatrixClient(host)

try:
    client.login(username, password)
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

if len(sys.argv) > 4:
    userid = sys.argv[4]
else:
    userid = samples_common.get_input("UserID: ")

try:
    user = client.get_user(userid)
    print("Display Name: %s" % user.get_display_name())
    print("Avatar %s" % user.get_avatar_url())
except MatrixRequestError as e:
    print(e)
    if e.code == 400:
        print("User ID/Alias in the wrong format")
        sys.exit(11)
    else:
        print("Couldn't find room.")
        sys.exit(12)
