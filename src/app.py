import os
from typing import Final
from urllib.parse import quote

import asyncio

from sanic.response import html
from sanic import Sanic, Request, HTTPResponse
from jinja2 import Environment, FileSystemLoader, select_autoescape

from src.utils import load_dotenv
from src.bot import bot as discord_bot


CURRENT_DIRECTORY_PATH: Final[str] = os.path.dirname(os.path.abspath(__file__))

load_dotenv()
PORT = os.getenv("PORT")
HOST = os.getenv("HOST")

CLIENT_ID = os.getenv("CLIENT_ID")
REDIRECT_URI = quote("https://" + os.getenv("REDIRECT_URI", "example.com"))

TURNSTILE_SITE_KEY = os.getenv("TURNSTILE_SITE_KEY")
TURNSTILE_SITE_SECRET = os.getenv("TURNSTILE_SITE_SECRET")

app = Sanic("ChallengeBots")


def render_template(template_name: str, **context) -> str:
    """
    Renders an HTML template with the given context.

    Args:
        template_name (str): The name of the template file to be rendered. 
                             If it does not end with '.html', this suffix will be added.
        **context: Arbitrary keyword arguments that will be passed to the template for rendering.

    Returns:
        str: The rendered HTML as a string.
    """

    if not template_name.endswith(".html"):
        template_name += ".html"

    template_dir = os.path.join(CURRENT_DIRECTORY_PATH,  'src', 'templates')
    env = Environment(
        loader=FileSystemLoader(template_dir),
        autoescape=select_autoescape(['html', 'xml'])
    )

    template = env.get_template(template_name)

    return template.render(**context)


@app.route("/", methods = ["GET", "POST"])
async def index(_: Request) -> HTTPResponse:
    template = render_template(
        "index", client_id = CLIENT_ID,
        redirect_uri = REDIRECT_URI,
        cf_turnstile_site_key = TURNSTILE_SITE_KEY
    )

    return html(template)


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


if __name__ == "__main__":
    asyncio.run(run_app())
