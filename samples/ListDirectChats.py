#!/usr/bin/env python3

# Dump the list of direct chats
# Args: host:port username password
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

room_ids = []

import yaml
print(yaml.dumps(client.account_data['m.direct']), default_flow_style=False)
