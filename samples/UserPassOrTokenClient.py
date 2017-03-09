#!/usr/bin/env python3
"""
Get a users room list and indicate login type.

to use user+pass to login and get a token:
    arg usage: --host 'host' --user 'username' --password 'password'
to use user+token to login:
    arg usage: --host 'host' --user 'username' --token 'token'
"""

import argparse
from matrix_client.client import MatrixClient


def _example(host, user, password, token):
    """run the example."""
    client = None
    if token:
        print('token login')
        client = MatrixClient(host, token=token, user_id=user)
    else:
        print('password login')
        client = MatrixClient(host)
        token = client.login_with_password(user, password)
        print('got token: %s' % token)
    for room_id, room in client.get_rooms().items():
        print("is in room %s" % room_id)


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
    try:
        _example(args.host, args.user, args.password, args.token)
    except Exception as e:
        print(e)
        exit(1)


if __name__ == "__main__":
    main()
