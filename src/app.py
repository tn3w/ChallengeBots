import os
import pickle
from urllib.parse import quote
from typing import Optional, Tuple
from datetime import datetime, timezone, timedelta

import asyncio

from sanic import Sanic, Request, HTTPResponse
from sanic.response import text, html, redirect
from jinja2 import Environment, FileSystemLoader, select_autoescape

from src.bot import has_role, verify_user

from src.logger import log
from src.crypto.symmetric import AES256
from src.database import get_database, get_database_decrypted
from src.utils import load_dotenv, generate_secure_string, http_request
from src.files import CURRENT_DIRECTORY_PATH, DATA_DIRECTORY_PATH, write, read
from src.discordauth import User, is_valid_oauth_code, get_access_token, get_user_info


load_dotenv()
PORT = os.getenv("PORT")
HOST = os.getenv("HOST")
HOSTNAME = os.getenv("HOSTNAME", "")

CERT_FILE_PATH = os.getenv("CERT_FILE_PATH")
KEY_FILE_PATH = os.getenv("KEY_FILE_PATH")

CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
REDIRECT_URI = "https://" + HOSTNAME
QUOTED_REDIRECT_URI = quote(REDIRECT_URI)

TURNSTILE_SITE_KEY = os.getenv("TURNSTILE_SITE_KEY")
TURNSTILE_SITE_SECRET = os.getenv("TURNSTILE_SITE_SECRET")

SESSION_KEY_FILE_PATH = os.path.join(DATA_DIRECTORY_PATH, "session.key")

SESSION_KEY = None
if os.path.join(SESSION_KEY_FILE_PATH):
    session_key_content = read(SESSION_KEY_FILE_PATH)
    if session_key_content and len(session_key_content) != 36:
        SESSION_KEY = session_key_content

if SESSION_KEY is None:
    SESSION_KEY = generate_secure_string(36)
    write(SESSION_KEY, SESSION_KEY_FILE_PATH, as_thread = True)

SESSION_AES = AES256(SESSION_KEY, serialization = "base62")

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


def render_callback(user: User, error: Optional[str] = None) -> str:
    """
    Renders the verified template with the provided user information.

    Args:
        user (User): The User object containing information about the user,
            including avatar URL, username, and discriminator.
        error (Optional[str]): An optional error message to display. If provided,
            it will be included in the rendered template.

    Returns:
        str: The rendered HTML string of the verified template.
    """

    return render_template(
        "callback", avatar_url = user.avatar_url,
        user_name = user.user_name, discriminator = user.discriminator,
        error = error
    )


def render_login_redirect(state: Optional[str] = None) -> HTTPResponse:
    """
    Generates a redirect response to initiate the Discord OAuth2 login process.

    Args:
        state (Optional[str]): An optional state parameter to maintain state between
            the request and callback. This can be used for CSRF protection or to
            store information about the user's session.

    Returns:
        HTTPResponse: A redirect response to the constructed authorization URL.
    """

    if state == "err":
        return text("Error") # FIXME

    if not state:
        state = "err"

    url = (
        f"https://discord.com/oauth2/authorize?client_id={CLIENT_ID}&redirect_uri=" +
        QUOTED_REDIRECT_URI + "%2Fauth&response_type=code&scope=guilds+identify&state=" + state
    )
    return redirect(url)


def response_set_cookies(request: Request, response: HTTPResponse, cookies: dict) -> HTTPResponse:
    """
    Sets cookies in the HTTP response based on the provided cookie dictionary.

    Args:
        request (Request): The HTTP request object, used to determine the scheme 
                           (HTTP or HTTPS) for setting the secure flag.
        response (HTTPResponse): The HTTP response object to which cookies will be added.
        cookies (dict): A dictionary of cookies to set, where keys are cookie names 
                        and values are cookie values.

    Returns:
        HTTPResponse: The modified HTTP response object with the cookies set.
    """

    cookie_settings = {
        "path": "/",
        "samesite": "Strict",
        "httponly": True,
        "secure": request.scheme == "https",
        "max_age": 604800 # 7 days
    }

    for key, value in cookies.items():
        response.cookies.add_cookie(key, value, **cookie_settings)

    return response


@app.route("/", methods = ["GET", "POST"])
async def index(_: Request) -> HTTPResponse:
    """
    Handles requests to the root URL ("/") of the application.

    Args:
        _: Request: The incoming request object. The parameter is named with an 
                    underscore to indicate that it is unused in this function.

    Returns:
        HTTPResponse: The HTML response containing the rendered "index" template.
    """

    template = render_template(
        "index", client_id = CLIENT_ID,
        redirect_uri = QUOTED_REDIRECT_URI,
        cf_turnstile_site_key = TURNSTILE_SITE_KEY
    )

    return html(template)


def create_session(user: User, access_token: str) -> str:
    user_info = user.user_info
    dumped_user_info = pickle.dumps(user_info)
    encrypted_user_info = AES256(access_token, serialization = "bytes").encrypt(dumped_user_info)

    sessions = get_database("sessions", 604800) # 7 days
    sessions[str(user.user_id)] = encrypted_user_info

    session_token = SESSION_AES.encrypt(str(user.user_id) + "/" + access_token)
    return session_token


def get_session(session_token: str) -> Tuple[User, str]:
    try:
        decrypted_session_token = SESSION_AES.decrypt(session_token).decode("utf-8")
        user_id, access_token = decrypted_session_token.split("/", 1)
    except Exception as exc:
        log(exc, level = 4)
        return None

    sessions = get_database("sessions", 604800) # 7 days
    encrypted_user_info = sessions[user_id]
    try:
        decrypted_user_info = AES256(
            access_token, serialization = "bytes"
        ).decrypt(encrypted_user_info)

        loaded_user_info = pickle.loads(decrypted_user_info)
    except Exception as exc:
        log(exc, level = 4)
        return None

    user = User(loaded_user_info)

    return user, access_token


def verify_turnstile(turnstile_response: str, turnstile_site_secret: str) -> bool:
    data = {
        "secret": turnstile_site_secret,
        "response": turnstile_response
    }

    url = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
    response = http_request(url, "POST", is_json = True, data = data)

    if not response or not isinstance(response, dict):
        return False

    if not response.get("hostname", HOSTNAME) == HOSTNAME:
        return False

    if not response.get("success", False):
        return False

    timestamp_str = response.get('challenge_ts', None)

    try:
        challenge_time = datetime.strptime(timestamp_str, '%Y-%m-%dT%H:%M:%S.%fZ')
    except Exception as exception:
        log(exception, level = 4)
        return False

    if challenge_time.tzinfo is None:
        challenge_time = challenge_time.replace(tzinfo=timezone.utc)

    current_time = datetime.now(timezone.utc)
    if current_time - challenge_time > timedelta(minutes = 5):
        return False

    return response.get("success", False)


@app.route("/auth", methods=["GET", "POST"])
async def login_or_verify(request: Request) -> HTTPResponse:
    """
    Handles the authentication process for users.

    Args:
        request (Request): The incoming HTTP request object containing query parameters
            and session information.

    Returns:
        HTTPResponse: An HTTP response object that may redirect the user, render
            a template, or return an error message based on the outcome
            of the login or verification process.
    """

    code = request.args.get("code")
    state = request.args.get("state")

    if not code or not is_valid_oauth_code(code):
        return render_login_redirect(state)

    access_token = get_access_token(
        CLIENT_ID, CLIENT_SECRET,
        REDIRECT_URI + "/auth", code
    )

    if not access_token:
        return render_login_redirect(state)

    user = get_user_info(access_token)
    if user is None:
        return render_login_redirect(state)

    session_token = create_session(user, access_token)

    def set_cookie(response: HTTPResponse) -> HTTPResponse:
        return response_set_cookies(request, response, {"session": session_token})

    if not state:
        return set_cookie(redirect("/dashboard"))

    if state == "err":
        return set_cookie(text("Error")) # FIXME

    if len(state) != 20:
        return set_cookie(html(render_callback(user, "Invalid or expired session."), 400))

    states = get_database_decrypted("states", None)
    state_data = states.get(state)
    if not state_data:
        return set_cookie(html(render_callback(user, "Invalid or expired session."), 400))

    guild_id, role_id = state_data
    if has_role(role_id, guild_id, user.user_id):
        return set_cookie(html(render_callback(user)))

    verified_users = get_database("verified_users", 1200)

    if verified_users.exists(str(user.user_id)):
        is_verified = verify_user(guild_id, role_id, user, True)
        if not is_verified:
            return set_cookie(html(render_callback(user, "Failed to assign role."), 400))

        return set_cookie(html(render_callback(user)))

    return set_cookie(html(render_template(
        "challenge", avatar_url = user.avatar_url, user_name = user.user_name,
        discriminator = user.discriminator, state = state, session = session_token,
        cf_turnstile_site_key = TURNSTILE_SITE_KEY
    )))


@app.route("/callback", methods=["GET", "POST"])
async def callback(request: Request) -> HTTPResponse:
    if request.method.lower() == "get":
        return redirect("/")

    session_token = request.form.get("session")
    if session_token is None:
        session_token = request.cookies.get("session")

    if not session_token or not 100 < len(session_token) < 150:
        return text("Error") # FIXME

    user = get_session(session_token)[0]

    state = request.form.get("state")
    if len(state) != 20:
        return html(render_callback(user, "Invalid or expired session."), 400)

    states = get_database_decrypted("states", None)
    state_data = states.get(state)
    if not state_data:
        return html(render_callback(user, "Invalid or expired session."), 400)

    guild_id, role_id = state_data

    turnstile_response = request.form.get("cf-turnstile-response")
    if not verify_turnstile(turnstile_response, TURNSTILE_SITE_SECRET):
        return html(render_callback(user, "Verification of human identity failed."), 400)

    verified_users = get_database("verified_users", 1200)
    verified_users[str(user.user_id)] = None

    is_verified = verify_user(guild_id, role_id, user)
    if not is_verified:
        return html(render_callback(user, "Role assignment failed."), 400)

    return html(render_callback(user))


async def run_app() -> None:
    """
    Starts the app.

    Returns:
        None
    """

    ssl = None
    if not None in [CERT_FILE_PATH, KEY_FILE_PATH]:
        ssl = {
            "cert": CERT_FILE_PATH,
            "key": KEY_FILE_PATH
        }

    server = await app.create_server(
        port = PORT,
        host = HOST,
        return_asyncio_server = True,
        ssl = ssl
    )

    if server is None:
        return

    await server.startup()
    await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(run_app())
