"""
This is a asyncio wrapper for the matrix API class.
"""
import json
from asyncio import sleep
from urllib.parse import quote

from matrix_client.api import MatrixHttpApi, MATRIX_V2_API_PATH
from matrix_client.errors import MatrixError, MatrixRequestError


class AsyncHTTPAPI(MatrixHttpApi):
    """
    Contains all raw matrix HTTP client-server API calls using asyncio and coroutines.

    Usage:
        async def main():
            async with aiohttp.ClientSession() as session:
                mapi = AsyncHTTPAPI("http://matrix.org", session)
                resp = await mapi.get_room_id("#matrix:matrix.org")
                print(resp)


        loop = asyncio.get_event_loop()
        loop.run_until_complete(main())
    """

    def __init__(self, base_url, client_session, token=None,
                 identity=None, default_429_wait_ms=5000):
        self.base_url = base_url
        self.identity = identity
        self.token = token
        self.txn_id = 0
        self.validate_cert = True
        self.client_session = client_session
        self.default_429_wait_ms = default_429_wait_ms

    async def _send(self,
                    method,
                    path,
                    content=None,
                    query_params=None,
                    headers=None,
                    api_path=MATRIX_V2_API_PATH):

        args = self._prepare_send(method, content, query_params, headers, path, api_path)
        content, query_params, headers, endpoint = args

        while True:
            request = self.client_session.request(
                method,
                endpoint,
                params=query_params,
                data=content,
                headers=headers)

            async with request as response:
                if response.status == 429:
                    responsejson = await response.json()
                    await sleep(self._get_waittime(responsejson))

                elif response.status < 200 or response.status >= 300:
                    raise MatrixRequestError(
                        code=response.status, content=await response.text())

                else:
                    return await response.json()

    # We only need to re-define methods that do something after _send
    async def get_display_name(self, user_id):
        content = await self._send("GET", "/profile/%s/displayname" % user_id)
        return content.get('displayname', None)

    async def get_avatar_url(self, user_id):
        content = await self._send("GET", "/profile/%s/avatar_url" % user_id)
        return content.get('avatar_url', None)

    async def get_room_id(self, room_alias):
        """Get room id from its alias

        Args:
            room_alias(str): The room alias name.

        Returns:
            Wanted room's id.
        """
        content = await self._send(
            "GET",
            "/directory/room/{}".format(quote(room_alias)),
            api_path="/_matrix/client/r0")
        return content.get("room_id", None)
