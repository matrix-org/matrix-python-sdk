#!/usr/bin/env python3

# Get a users display name and avatar
# Args: host:port username password user_id
# Error Codes:
# 2 - Could not find the server.
# 3 - Bad URL Format.
# 4 - Bad username/password.

import sys
import samples_common

from matrix_client.client import MatrixClient
from matrix_client.api import MatrixRequestError
from requests.exceptions import MissingSchema


host, username, password = samples_common.get_user_details(sys.argv)

client = MatrixClient(host)

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

user = client.get_user(client.user_id)
print("Current Display Name: %s" % user.get_display_name())

displayname = input("New Display Name: ")
user.set_display_name(displayname)
