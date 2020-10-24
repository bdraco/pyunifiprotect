import asyncio
import json
import logging
import time

import aiohttp
from aiohttp import ClientSession, CookieJar

from pyunifiprotect.unifi_protect_server import UpvServer

UFP_USERNAME = "YOUR USERNAME"
UFP_PASSWORD = "YOUR PASSWORD"
UFP_IPADDRESS = "IP ADDRESS OF UFP"
UFP_PORT = 443


async def event_data():
    session = ClientSession(cookie_jar=CookieJar(unsafe=True))

    # Log in to Unifi Protect
    unifiprotect = UpvServer(
        session,
        UFP_IPADDRESS,
        UFP_PORT,
        UFP_USERNAME,
        UFP_PASSWORD,
    )

    await unifiprotect.update()

    for i in range(15000):
        data = await unifiprotect.get_raw_events(10)
        await asyncio.sleep(1)

    # Close the Session
    await session.close()


logging.basicConfig(level=logging.DEBUG)
loop = asyncio.get_event_loop()
loop.run_until_complete(event_data())
loop.close()
