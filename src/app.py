import os
import re
from typing import Optional
from functools import lru_cache
from datetime import datetime, timezone, timedelta
from urllib.parse import urlunparse, urlparse, quote

import asyncio

from sanic.exceptions import NotFound
from sanic.response import text, html, redirect, json
from sanic import Sanic, Request, HTTPResponse, SanicException
from jinja2 import Environment, FileSystemLoader, select_autoescape

from src.logger import log
from src.utils import load_dotenv, http_request
from src.sanic_errors import ERROR_INFOS, handle_all_errors
from src.database import get_database, get_database_decrypted
from src.bot import has_role, verify_user, get_guilds, get_oauth_url
from src.files import CURRENT_DIRECTORY_PATH, WELL_KNOWN_DIRECTORY_PATH, read
from src.discordauth import (
    User, is_valid_oauth_code, get_access_token, get_user_info, create_session,
    set_session, get_session, is_session_token_valid, get_user_guilds
)


load_dotenv()
PORT = os.getenv("PORT")
HOST = os.getenv("HOST")
HOSTNAME = os.getenv("HOSTNAME", "")
LONG_HOSTNAME = os.getenv("LONG_HOSTNAME")

CERT_FILE_PATH = os.getenv("CERT_FILE_PATH")
KEY_FILE_PATH = os.getenv("KEY_FILE_PATH")

CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
REDIRECT_URI = "https://" + HOSTNAME
QUOTED_REDIRECT_URI = quote(REDIRECT_URI)

TURNSTILE_SITE_KEY = os.getenv("TURNSTILE_SITE_KEY")
TURNSTILE_SITE_SECRET = os.getenv("TURNSTILE_SITE_SECRET")

app = Sanic("ChallengeBots")


def render_error(title: str, description: str, code: int = 404) -> str:
    """
    Renders the error template with the specified title, description, and HTTP error code.

    Args:
        title (str): The title of the error to display in the rendered template.
        description (str): A detailed description of the error for the user.
        code (int, optional): The HTTP error code to display. Defaults to 400.

    Returns:
        str: The rendered HTML string of the error template.
    """

    return render_template(
        "error", title = title,
        description = description,
        code = str(code)
    )


def handle_error(_: Request = None, exception: SanicException = NotFound) -> HTTPResponse:
    """
    Handles errors by rendering an appropriate error page based on the exception's status code.

    Args:
        _ (Request): The Sanic request object. Unused in this function.
        exception (SanicException): The exception raised, containing the status code to be handled.

    Returns:
        HTTPResponse: An HTML response displaying the error page with a title, description,
                      and code based on the exception details.
    """

    status_code = getattr(exception, "status_code", 400)

    error_info = ERROR_INFOS.get(status_code, {
        "code": 400,
        "title": "Something happened",
        "description": ("Like a black hole that irrevocably devours "
                        "data and processes and leaves no answers behind.")
    })

    return html(render_error(**error_info))


def handle_not_found() -> HTTPResponse:
    """
    Returns an HTTP response for a "Not Found" error.

    Returns:
        HTTPResponse: The HTTP response with a 404 Not Found error status.
    """

    return handle_error(exception = NotFound)


handle_all_errors(app, handle_error)


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


def text_to_markdown(markdown_text: str) -> str:
    """
    Converts a Markdown-formatted string into HTML.

    Args:
        markdown_text (str): The input Markdown string to be converted.

    Returns:
        str: The resulting HTML string with all Markdown formatting converted.
    """

    markdown_text = re.sub(r'###### (.+)', r'<h6>\1</h6>', markdown_text)
    markdown_text = re.sub(r'##### (.+)', r'<h5>\1</h5>', markdown_text)
    markdown_text = re.sub(r'#### (.+)', r'<h4>\1</h4>', markdown_text)
    markdown_text = re.sub(r'### (.+)', r'<h3>\1</h3>', markdown_text)
    markdown_text = re.sub(r'## (.+)', r'<h2>\1</h2>', markdown_text)
    markdown_text = re.sub(r'# (.+)', r'<h1>\1</h1>', markdown_text)

    markdown_text = re.sub(r'\*\*\*(.+?)\*\*\*', r'<b><i>\1</i></b>', markdown_text)
    markdown_text = re.sub(r'\*\*(.+?)\*\*', r'<b>\1</b>', markdown_text)
    markdown_text = re.sub(r'\*(.+?)\*', r'<i>\1</i>', markdown_text)

    markdown_text = re.sub(r'\[(.*?)\]\((.*?)\)', r'<a href="\2">\1</a>', markdown_text)

    markdown_text = re.sub(r'```([^`]+)```', r'<pre><code>\1</code></pre>', markdown_text)
    markdown_text = re.sub(r'`([^`]+)`', r'<code>\1</code>', markdown_text)

    markdown_text = re.sub(r'(?m)^- (.+)', r'<ul><li>\1</li></ul>', markdown_text)
    markdown_text = re.sub(r'(?m)^(\d+)\. (.+)', r'<ol><li>\2</li></ol>', markdown_text)

    return markdown_text


def clean_markdown(markdown_text: str) -> str:
    """
    Removes specific Markdown formatting and hyperlinks from a string.

    Args:
        markdown_text (str): The input Markdown string to be cleaned.

    Returns:
        str: The cleaned Markdown text with specific elements removed.
    """

    markdown_text = re.sub(r'\[.*?\]\((https?://[^\s]+)\)', r'\1', markdown_text)
    markdown_text = markdown_text.replace("**", "")
    markdown_text = markdown_text.replace("<br>", "")

    return markdown_text


def render_markdown(file_name: str, markdown_text: str) -> str:
    """
    Renders an HTML template with Markdown content converted to HTML.

    Args:
        file_name (str): The name of the HTML template file.
        markdown_text (str): The Markdown text to convert and render in the template.

    Returns:
        str: The HTML string of the rendered template with Markdown content.
    """

    rendered_markdown = text_to_markdown(markdown_text)

    return render_template(
        "markdown", file_name = file_name,
        rendered_markdown = rendered_markdown
    )


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


@lru_cache
def render_maintenance() -> str:
    """
    Renders the maintenance page template.

    Returns:
        str: The rendered HTML content of the maintenance page.
    """

    return render_template("maintenance")


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
        return render_error("Forbidden", "The client is in an error state.", 403)

    if not state:
        state = "err"

    return redirect(get_oauth_url(state))


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


if LONG_HOSTNAME is not None:
    @app.middleware("request")
    async def redirect_to_long_hostname(request: Request):
        """
        Middleware that redirects requests to a specified long hostname if the request
        path is not '/auth' or '/callback' and the current hostname is different from
        the specified LONG_HOSTNAME.

        Args:
            request (Request): The incoming HTTP request.

        Returns:
            HTTPResponse: A redirect response to the new URL with the long hostname
                if the conditions are met; otherwise, the request proceeds normally.
        """

        current_url = request.url
        parsed_url = urlparse(current_url)
        current_hostname = parsed_url.hostname
        path = parsed_url.path
        query = parsed_url.query
        fragment = parsed_url.fragment

        if (path in ("/", "/dashboard", "/privacy", "/security", "/terms", "/dnt") \
            or path.startswith("/.well-known")) \
            and current_hostname != LONG_HOSTNAME:

            new_url = urlunparse(
                ("https", LONG_HOSTNAME, path, "", query, fragment)
            )
            return redirect(new_url)


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
        cf_turnstile_site_key = TURNSTILE_SITE_KEY,
        long_hostname = LONG_HOSTNAME or HOSTNAME,
        guilds = len(await get_guilds())
    )

    return html(template)


@app.route("/robots.txt", methods = ["GET", "POST"])
async def robots(_: Request) -> HTTPResponse:
    """
    Handles requests to "/robots.txt" to provide instructions for web crawlers.

    Args:
        _: Request: The incoming request object. The parameter is named with an 
                    underscore to indicate that it is unused in this function.

    Returns:
        HTTPResponse: A plain text response containing directives for web crawlers.
    """

    return text("User-agent: *\nDisallow:")


def verify_turnstile(turnstile_response: str, turnstile_site_secret: str) -> bool:
    """
    Verifies the user's identity using Cloudflare's Turnstile CAPTCHA verification.

    Args:
        turnstile_response (str): The CAPTCHA response token from the user's submission.
        turnstile_site_secret (str): The secret key used to authenticate with
            the Turnstile API.

    Returns:
        bool: True if the CAPTCHA verification is successful, False otherwise.
    """

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


@app.route("/dashboard", methods=["GET", "POST"])
async def dash(request: Request) -> HTTPResponse:
    """
    Handles the dashboard page for authenticated users.

    Args:
        request (Request): The incoming HTTP request object, containing query parameters
            such as `state` and cookies, including the `session` cookie for the user's session.

    Returns:
        HTTPResponse: An HTTP response object that either renders the dashboard information
            in JSON format, redirects to the login page, or sets a session cookie when needed.
    """

    state = request.args.get("state")

    set_cookie = False

    session_token = request.cookies.get("session")
    if session_token is None:
        session_token = request.args.get("session")
        set_cookie = True

    def optional_cookie(response: HTTPResponse) -> HTTPResponse:
        if not set_cookie:
            return response

        return response_set_cookies(request, response, {"session": session_token})

    if not is_session_token_valid(session_token):
        return render_login_redirect(state)

    if session_token.endswith("."):
        return optional_cookie(render_login_redirect(state))

    user, access_token = get_session(session_token)

    if None in [user, access_token]:
        return optional_cookie(render_login_redirect(state))

    if (guilds := user.guilds) is None:
        guilds = get_user_guilds(access_token)
        if guilds is None:
            return optional_cookie(render_login_redirect(state))

        user.set_guilds(guilds)
        set_session(user, access_token)

    if not isinstance(guilds, list):
        return optional_cookie(render_login_redirect(state))

    return optional_cookie(html(render_maintenance()))
    #return optional_cookie(json([guild.guild_info for guild in guilds]))


@app.route("/auth", methods=["GET", "POST"])
async def auth(request: Request) -> HTTPResponse:
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

    if not state or state == "err":
        return set_cookie(redirect("/dashboard?session=" + str(session_token)))

    session_token += "."

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
    """
    Processes the callback for role verification after the initial authentication process.

    Args:
        request (Request): The incoming HTTP request object containing form data,
            cookies, and session information.

    Returns:
        HTTPResponse: An HTTP response object that confirms the verification process outcome,
            either completing the process or returning an error if validation fails.
    """

    if request.method.lower() == "get":
        return redirect("/")

    session_token = request.form.get("session")
    if session_token is None:
        session_token = request.cookies.get("session")

    if not is_session_token_valid(session_token):
        return render_error("Unauthorized", "The current session is invalid.", 401)

    user = get_session(session_token)[0]

    if not user:
        return render_error("Unauthorized", "The current session is invalid.", 401)

    state = request.form.get("state")
    if len(state) != 20:
        return html(render_callback(user, "Invalid or expired state."), 400)

    states = get_database_decrypted("states", None)
    state_data = states.get(state)
    if not state_data:
        return html(render_callback(user, "Invalid or expired state."), 400)

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


@app.route("/<file_name>")
@lru_cache()
async def markdown_files(_: Request, file_name: Optional[str] = None) -> HTTPResponse:
    """
    Serves an HTML-rendered Markdown policy file for specific endpoints.

    Args:
        _ (Request): The incoming HTTP request object.
        file_name (Optional[str]): The name of the policy file to retrieve, without file extension.

    Returns:
        HTTPResponse: The HTTP response containing the rendered HTML of the policy file.
    """

    if not file_name in ["security", "privacy", "dnt"]:
        return handle_not_found()

    file_path = os.path.join(WELL_KNOWN_DIRECTORY_PATH, file_name + "-policy.md")
    file_content = read(file_path)
    if file_content is None:
        return handle_not_found()

    return html(render_markdown(file_name, file_content))


@app.route("/.well-known/<file_name>")
@lru_cache()
async def well_known_files(_: Request, file_name: Optional[str] = None) -> HTTPResponse:
    """
    Serves raw or cleaned Markdown policy files for well-known endpoints.

    Args:
        _ (Request): The incoming HTTP request object.
        file_name (Optional[str]): The file name for the policy, including ".txt" extension.

    Returns:
        HTTPResponse: The HTTP response containing the policy file content as plain text.
    """

    if not file_name in ["security.txt", "security-policy.txt", "dnt-policy.txt"]:
        return handle_not_found()

    file_path = os.path.join(WELL_KNOWN_DIRECTORY_PATH, file_name.replace(".txt", "") + ".md")
    file_content = read(file_path)
    if file_content is None:
        return handle_not_found()

    if file_name != "dnt-policy.txt":
        file_content = clean_markdown(file_content)

    return text(file_content)


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


def main() -> None:
    """
    Entry point for the application.

    Returns:
        None
    """

    asyncio.run(run_app())


if __name__ == "__main__":
    main()
