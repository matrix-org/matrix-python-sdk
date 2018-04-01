# Common functions for sample code.

from getpass import getpass

try:
    get_input = raw_input
except NameError:
    get_input = input


def get_user_details(argv):
    try:
        host = argv[1]
    except IndexError:
        host = get_input("Host (ex: http://localhost:8008 ): ")

    try:
        username = argv[2]
    except IndexError:
        username = get_input("Username: ")

    try:
        password = argv[3]
    except IndexError:
        password = getpass()  # Hide user input

    return host, username, password
