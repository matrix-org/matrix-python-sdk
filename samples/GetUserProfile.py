#!/usr/bin/env python3

# Get a users display name and avatar
# Args: host:port username password user_id
# Error Codes:
# 2 - Could not find the server.
# 3 - Bad URL Format.
# 4 - Bad username/password.
# 11 - Wrong room format.
# 12 - Couldn't find room.


import sys

from matrix_client.client import MatrixClient
from matrix_client.api import MatrixRequestError
from requests.exceptions import MissingSchema
from getpass import getpass

if len(sys.argv) > 1:
    host = sys.argv[1]
else:
    host = input("Host (ex: http://localhost:8008 ): ")

client = MatrixClient(host)

if len(sys.argv) > 2:
    username = sys.argv[2]
else:
    username = input("Username: ")

if len(sys.argv) > 3:
    password = sys.argv[3]
else:
    password = getpass()  # Hide user input

try:
    client.login_with_password(username, password)
except MatrixRequestError as e:
    print(e)
    if e.code == 403:
        print("Bad username or password.")
        sys.exit(4)
    else:
        print("Check your sever details are correct.")
        sys.exit(3)

except MissingSchema as e:
    print("Bad URL format.")
    print(e)
    sys.exit(2)

if len(sys.argv) > 4:
    userid = sys.argv[4]
else:
    userid = input("UserID: ")

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
