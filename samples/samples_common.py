# Common functions for sample code.

import sys

from getpass import getpass

try:
    get_input = raw_input
except NameError:
    get_input = input


def get_user_details():
    if len(sys.argv) > 1:
        host = sys.argv[1]
    else:
        host = get_input("Host (ex: http://localhost:8008 ): ")

    if len(sys.argv) > 2:
        username = sys.argv[2]
    else:
        username = get_input("Username: ")

    if len(sys.argv) > 3:
        password = sys.argv[3]
    else:
        password = getpass()  # Hide user input

    return host, username, password
