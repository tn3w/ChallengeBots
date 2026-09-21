import asyncio
import json
import logging
import os
import secrets
import urllib.error
import urllib.parse
import urllib.request
from functools import wraps

import discord
from flask import (
    Flask,
    abort,
    jsonify,
    make_response,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from src import database
from src.bot import bot, grant_role, publish_verification, role_problem

logger = logging.getLogger(__name__)

DISCORD_API = "https://discord.com/api"
USER_AGENT = "ChallengeBots (https://github.com/tn3w/ChallengeBots, 2.0)"
MANAGE_PERMISSIONS = 0x8 | 0x20
BOT_PERMISSIONS = 2415919104
BOT_TIMEOUT_SECONDS = 15

CLIENT_ID = os.getenv("CLIENT_ID", "")
CLIENT_SECRET = os.getenv("CLIENT_SECRET", "")
HCAPTCHA_SITE_KEY = os.getenv("HCAPTCHA_SITE_KEY", "10000000-ffff-ffff-ffff-000000000001")
HCAPTCHA_SECRET = os.getenv(
    "HCAPTCHA_SITE_SECRET", "0x0000000000000000000000000000000000000000"
)

app = Flask(__name__, template_folder="../templates")
app.secret_key = os.getenv("SECRET_KEY") or secrets.token_hex(32)
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")


def failure(message: str, status: int = 400):
    return make_response(jsonify(success=False, error=message), status)


def deny(message: str, status: int = 400):
    abort(failure(message, status))


def http_json(url: str, data: dict | None = None, token: str | None = None):
    headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    body = urllib.parse.urlencode(data).encode() if data else None
    with urllib.request.urlopen(
        urllib.request.Request(url, body, headers), timeout=10
    ) as response:
        return json.load(response)


def run_on_bot(coroutine):
    future = asyncio.run_coroutine_threadsafe(coroutine, bot.loop)
    return future.result(timeout=BOT_TIMEOUT_SECONDS)


def verify_hcaptcha(response: str) -> bool:
    try:
        data = {"secret": HCAPTCHA_SECRET, "response": response}
        return http_json("https://api.hcaptcha.com/siteverify", data).get(
            "success", False
        )
    except (urllib.error.URLError, TimeoutError, ValueError):
        return False


def rate_limit(seconds: int):
    def decorator(view):
        @wraps(view)
        def wrapped(*arguments, **keyword_arguments):
            if database.is_rate_limited(request.remote_addr, view.__name__, seconds):
                return failure("Rate limit exceeded. Please try again later.", 429)
            return view(*arguments, **keyword_arguments)

        return wrapped

    return decorator


def login_required(view):
    @wraps(view)
    def wrapped(*arguments, **keyword_arguments):
        if "user_token" not in session:
            return jsonify(
                success=False, error="Authentication required", logged_in=False
            ), 401
        return view(*arguments, **keyword_arguments)

    return wrapped


def managed_servers() -> list[dict]:
    user_id = session["user_id"]
    servers = database.get_cached_servers(user_id)
    if servers is not None:
        return servers

    guilds = http_json(f"{DISCORD_API}/users/@me/guilds", token=session["user_token"])
    servers = [
        {"id": guild["id"], "name": guild["name"], "icon": guild_icon(guild)}
        for guild in guilds
        if int(guild.get("permissions", 0)) & MANAGE_PERMISSIONS
    ]
    database.cache_servers(user_id, servers)
    return servers


def guild_icon(guild: dict) -> str:
    if not guild.get("icon"):
        return "https://cdn.discordapp.com/embed/avatars/0.png"
    return f"https://cdn.discordapp.com/icons/{guild['id']}/{guild['icon']}.png"


def require_manager(guild_id: str) -> None:
    if not any(server["id"] == guild_id for server in managed_servers()):
        deny("You don't manage this server", 403)


def managed_guild(guild_id: str) -> discord.Guild:
    require_manager(guild_id)
    if not bot.is_ready():
        deny("Bot is not connected", 503)
    guild = bot.get_guild(int(guild_id))
    if guild is None:
        deny("Bot is not in this server", 404)
    return guild


def owned_verification(guild_id: str, verification_id: str) -> dict:
    verification = database.get_verification(verification_id)
    if not verification or verification["guild_id"] != guild_id:
        deny("Verification not found", 404)
    return verification


def invite_url(guild_id: str) -> str:
    parameters = {
        "client_id": CLIENT_ID,
        "permissions": BOT_PERMISSIONS,
        "scope": "bot",
        "guild_id": guild_id,
        "disable_guild_select": "true",
    }
    return f"https://discord.com/oauth2/authorize?{urllib.parse.urlencode(parameters)}"


@app.errorhandler(urllib.error.URLError)
def discord_unreachable(error):
    logger.error("Discord API error: %s", error)
    return failure("Could not reach Discord", 502)


@app.route("/")
def index():
    guild_count = len(bot.guilds) if bot.is_ready() else 0
    return render_template(
        "index.html",
        site_key=HCAPTCHA_SITE_KEY,
        client_id=CLIENT_ID,
        guild_count=guild_count,
    )


@app.route("/dashboard")
@app.route("/dashboard/<guild_id>")
def dashboard(guild_id=None):
    return render_template("dash.html", guild_id=guild_id)


@app.route("/verify")
def verify():
    return render_template("verify.html", site_key=HCAPTCHA_SITE_KEY)


@app.route("/auth")
def auth():
    code = request.args.get("code")
    if not code:
        return redirect(url_for("index"))

    token_data = http_json(
        f"{DISCORD_API}/oauth2/token",
        {
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": request.base_url,
        },
    )
    user = http_json(f"{DISCORD_API}/users/@me", token=token_data["access_token"])
    avatar = (
        f"https://cdn.discordapp.com/avatars/{user['id']}/{user['avatar']}.png"
        if user.get("avatar")
        else "https://cdn.discordapp.com/embed/avatars/0.png"
    )

    session.clear()
    session.update(
        user_token=token_data["access_token"],
        user_id=user["id"],
        username=user.get("global_name") or user["username"],
        discriminator=user.get("discriminator", "0"),
        avatar=avatar,
    )
    database.clear_servers(user["id"])
    return redirect(url_for("dashboard"))


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


@app.route("/api/user")
def current_user():
    if "user_id" not in session:
        return jsonify(success=True, logged_in=False)
    return jsonify(
        success=True,
        logged_in=True,
        **{
            key: session[key]
            for key in ("user_id", "username", "discriminator", "avatar")
        },
    )


@app.route("/api/servers")
@login_required
def servers():
    bot_guild_ids = {str(guild.id) for guild in bot.guilds} if bot.is_ready() else set()
    return jsonify(
        success=True,
        servers=[
            {**server, "has_bot": server["id"] in bot_guild_ids}
            for server in managed_servers()
        ],
        client_id=CLIENT_ID,
        redirect_uri=request.host_url + "auth",
    )


@app.route("/api/guild/<guild_id>")
@login_required
def guild_info(guild_id):
    require_manager(guild_id)
    guild = bot.get_guild(int(guild_id)) if bot.is_ready() else None
    if guild is None:
        return jsonify(
            success=True,
            bot_in_guild=False,
            guild_id=guild_id,
            invite_url=invite_url(guild_id),
        )

    channels = [
        {"id": str(channel.id), "name": channel.name, "position": channel.position}
        for channel in sorted(guild.text_channels, key=lambda channel: channel.position)
    ]
    roles = [
        {
            "id": str(role.id),
            "name": role.name,
            "color": str(role.color),
            "position": role.position,
        }
        for role in reversed(guild.roles)
        if not role.is_default() and role < guild.me.top_role
    ]
    return jsonify(
        success=True,
        bot_in_guild=True,
        guild_id=guild_id,
        channels=channels,
        roles=roles,
        verifications=database.list_verifications(guild_id),
    )


def verification_fields(data: dict) -> dict:
    names = (
        "captcha_type",
        "embed_title",
        "embed_description",
        "embed_color",
        "embed_footer",
    )
    return {name: data[name] for name in names if data.get(name) is not None}


def checked_role(guild: discord.Guild, role_id) -> discord.Role:
    role = guild.get_role(int(role_id))
    if role is None:
        deny("Invalid role")
    problem = role_problem(guild, role)
    if problem:
        deny(problem)
    return role


def publish(verification_id: str):
    error = run_on_bot(publish_verification(verification_id))
    if error:
        return failure(error)
    return jsonify(success=True, verification_id=verification_id)


@app.route("/api/guild/<guild_id>/verification", methods=["POST"])
@login_required
def create_verification(guild_id):
    data = request.get_json(silent=True) or {}
    if not data.get("channel_id") or not data.get("role_id"):
        return failure("Missing channel or role")

    guild = managed_guild(guild_id)
    channel = guild.get_channel(int(data["channel_id"]))
    if not isinstance(channel, discord.TextChannel):
        return failure("Invalid channel")
    role = checked_role(guild, data["role_id"])

    verification_id = database.save_verification(
        guild_id, str(channel.id), role_id=str(role.id), **verification_fields(data)
    )
    return publish(verification_id)


@app.route("/api/guild/<guild_id>/verification/<verification_id>", methods=["PUT"])
@login_required
def update_verification(guild_id, verification_id):
    data = request.get_json(silent=True) or {}
    guild = managed_guild(guild_id)
    owned_verification(guild_id, verification_id)

    fields = verification_fields(data)
    if data.get("role_id"):
        fields["role_id"] = str(checked_role(guild, data["role_id"]).id)
    database.update_verification(verification_id, **fields)

    if data.get("update_message"):
        return publish(verification_id)
    return jsonify(success=True, verification_id=verification_id)


@app.route("/api/guild/<guild_id>/verification/<verification_id>", methods=["DELETE"])
@login_required
def delete_verification(guild_id, verification_id):
    require_manager(guild_id)
    owned_verification(guild_id, verification_id)
    database.delete_verification(verification_id)
    return jsonify(success=True)


@app.route("/api/verify-tokens")
@rate_limit(1)
def verify_tokens():
    user = database.get_user_token(request.args.get("token", ""))
    if not user or user["verification_id"] != request.args.get("verification_id"):
        return failure("Invalid or expired verification link")
    return jsonify(
        success=True,
        verification_id=user["verification_id"],
        user_token=user["token"],
        member_id=user["member_id"],
        username=user["username"],
        discriminator=user["discriminator"],
        avatar_url=user["avatar_url"],
    )


@app.route("/api/complete-verification", methods=["POST"])
@rate_limit(2)
def complete_verification():
    data = request.get_json(silent=True) or {}
    user = database.get_user_token(data.get("user_token", ""))
    if not user:
        return failure("Invalid or expired verification link")
    if not verify_hcaptcha(data.get("captcha_response", "")):
        return failure("CAPTCHA verification failed")

    verification = database.get_verification(user["verification_id"])
    if not verification:
        return failure("This verification no longer exists")

    error = run_on_bot(grant_role(verification, user["member_id"]))
    if error:
        return failure(error)
    database.remove_user_token(user["token"])
    return jsonify(
        success=True, message="Verification successful! You can return to Discord."
    )


async def run_app():
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "5000"))
    await asyncio.to_thread(app.run, host=host, port=port)
