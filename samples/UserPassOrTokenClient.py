#!/usr/bin/env python3
"""
Get a users room list and indicate login type.

to use user+pass to login and get a token:
    arg usage: --host 'host' --user 'username' --password 'password'
to use user+token to login:
    arg usage: --host 'host' --user 'username' --token 'token'
Error Codes:
1 - No password or token given (can't login)
2 - Combination of user + pass is incorrect/invalid
3 - Combination of user + token is incorrect/invalid
4 - Server details invalid/incorrect
5 - Malformed URL for connection
6 - Invalid URL schema
"""

import argparse
from matrix_client.client import MatrixClient
from matrix_client.api import MatrixRequestError
from requests.exceptions import MissingSchema, InvalidSchema


def example(host, user, password, token):
    """run the example."""
    client = None
    try:
        if token:
            print('token login')
            client = MatrixClient(host, token=token, user_id=user)
        else:
            print('password login')
            client = MatrixClient(host)
            token = client.login(user, password)
            print('got token: %s' % token)
    except MatrixRequestError as e:
        print(e)
        if e.code == 403:
            print("Bad username or password")
            exit(2)
        elif e.code == 401:
            print("Bad username or token")
            exit(3)
        else:
            print("Verify server details.")
            exit(4)
    except MissingSchema as e:
        print(e)
        print("Bad formatting of URL.")
        exit(5)
    except InvalidSchema as e:
        print(e)
        print("Invalid URL schema")
        exit(6)
    print("is in rooms")
    for room_id, room in client.get_rooms().items():
        print(room_id)


def main():
    """Main entry."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", type=str, required=True)
    parser.add_argument("--user", type=str, required=True)
    parser.add_argument("--password", type=str)
    parser.add_argument("--token", type=str)
    args = parser.parse_args()
    if not args.password and not args.token:
        print('password or token is required')
        exit(1)
    example(args.host, args.user, args.password, args.token)


if __name__ == "__main__":
    main()
