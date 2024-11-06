import os

from sanic import Sanic

from utils import load_dotenv
from bot import bot as discord_bot


load_dotenv()
PORT = os.getenv("PORT")
HOST = os.getenv("HOST")

app = Sanic(__name__)


async def run_app() -> None:
    """
    Starts the app.

    Returns:
        None
    """

    server = await app.create_server(
        port = PORT,
        host = HOST,
        return_asyncio_server = True,
    )

    if server is None:
        return

    await server.startup()
    await server.serve_forever()
