# Common functions for sample code.

from getpass import getpass

try:
    get_input = raw_input
except NameError:
    get_input = input


def get_user_details(argv):
    if len(argv) > 1:
        host = argv[1]
    else:
        host = get_input("Host (ex: http://localhost:8008 ): ")

    if len(argv) > 2:
        username = argv[2]
    else:
        username = get_input("Username: ")

    if len(argv) > 3:
        password = argv[3]
    else:
        password = getpass()  # Hide user input

    return host, username, password
