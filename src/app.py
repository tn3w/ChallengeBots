import os
import asyncio
import logging
import json
import urllib.request
import urllib.parse
import secrets
from functools import wraps
import time

from flask import (
    Flask,
    Response,
    render_template,
    request,
    jsonify,
    redirect,
    session,
    url_for,
)
import discord
from src.utils import load_dotenv
from src.database import Database
from src.bot import bot, VerificationView

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__, template_folder="../templates")
app.secret_key = os.getenv("SECRET_KEY") or secrets.token_hex(16)

load_dotenv()
CLIENT_ID = os.getenv("CLIENT_ID", "1000000000000000000")
CLIENT_SECRET = os.getenv("CLIENT_SECRET", "")
REDIRECT_URI = urllib.parse.quote(
    os.getenv("REDIRECT_URI", "http://localhost:5000/auth")
)
HCAPTCHA_SITE_KEY = os.getenv(
    "HCAPTCHA_SITE_KEY", "10000000-ffff-ffff-ffff-000000000001"
)
HCAPTCHA_SECRET_KEY = os.getenv(
    "HCAPTCHA_SECRET_KEY", "0x0000000000000000000000000000000000000000"
)

OAUTH_USER_AGENT = "ChallengeBots (https://challengebots.tn3w.dev, v1.0)"

db = Database()


def get_guild_count():
    """Get the number of guilds (servers) the bot is connected to."""
    try:
        if not bot.is_ready():
            return 0
        count = len(bot.guilds)
        return count
    except Exception:
        return 0


def verify_hcaptcha(captcha_response):
    """Verify the hCaptcha response with the hCaptcha API."""
    data = {"secret": HCAPTCHA_SECRET_KEY, "response": captcha_response}
    encoded_data = urllib.parse.urlencode(data).encode("ascii")

    hcaptcha_request = urllib.request.Request(
        "https://hcaptcha.com/siteverify", data=encoded_data, method="POST"
    )

    try:
        with urllib.request.urlopen(hcaptcha_request, timeout=3) as response:
            result = json.loads(response.read().decode("utf-8"))
            return result.get("success", False)
    except Exception:
        return False


def rate_limit(limit_seconds=60):
    """Decorator to rate limit API endpoints by IP address."""

    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            ip = request.remote_addr
            if db.check_rate_limit(ip, f.__name__, limit_seconds):
                return (
                    jsonify(
                        {
                            "success": False,
                            "error": "Rate limit exceeded. Please try again later.",
                        }
                    ),
                    429,
                )
            return f(*args, **kwargs)

        return wrapped

    return decorator


def login_required(f):
    """Decorator to require login for API endpoints."""

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get("user_token"):
            return (
                jsonify(
                    {
                        "success": False,
                        "error": "Authentication required",
                        "logged_in": False,
                    }
                ),
                401,
            )
        return f(*args, **kwargs)

    return decorated_function


@app.route("/")
def index():
    """Redirect to home page."""
    return render_template(
        "index.html",
        site_key=HCAPTCHA_SITE_KEY,
        client_id=CLIENT_ID,
        redirect_uri=REDIRECT_URI,
        guild_count=get_guild_count(),
    )


@app.route("/dashboard")
@app.route("/dashboard/<guild_id>")
def dashboard(guild_id=None):
    """Render the dashboard page."""
    return render_template("dash.html", guild_id=guild_id)


@app.route("/auth")
def auth():
    """Handle OAuth callback from Discord."""
    code = request.args.get("code")
    if not code:
        return redirect(url_for("index"))

    data = {
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": request.base_url,
        "scope": "identify guilds",
    }

    try:
        encoded_data = urllib.parse.urlencode(data).encode("ascii")

        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": OAUTH_USER_AGENT,
            "Accept": "*/*",
        }

        oauth_request = urllib.request.Request(
            "https://discord.com/api/oauth2/token",
            data=encoded_data,
            method="POST",
            headers=headers,
        )

        with urllib.request.urlopen(oauth_request) as response:
            token_data = json.loads(response.read().decode("utf-8"))

        access_token = token_data["access_token"]
        refresh_token = token_data.get("refresh_token")
        expires_in = token_data.get("expires_in")

        token_expires_at = None
        if expires_in:
            token_expires_at = int(time.time()) + int(expires_in)

        session["user_token"] = access_token

        user_headers = {
            "Authorization": f"Bearer {access_token}",
            "User-Agent": OAUTH_USER_AGENT,
            "Accept": "application/json",
        }

        user_request = urllib.request.Request(
            "https://discord.com/api/users/@me",
            headers=user_headers,
        )

        with urllib.request.urlopen(user_request) as user_response:
            user_info = json.loads(user_response.read().decode("utf-8"))

        user_id = user_info["id"]
        username = user_info["username"]
        discriminator = user_info.get("discriminator", "0")
        avatar_hash = user_info.get("avatar")

        if avatar_hash:
            avatar_url = (
                f"https://cdn.discordapp.com/avatars/{user_id}/{avatar_hash}.png"
            )
        else:
            avatar_url = "https://cdn.discordapp.com/embed/avatars/0.png"

        db.store_discord_user(
            user_id=user_id,
            username=username,
            discriminator=discriminator,
            avatar_url=avatar_url,
            access_token=access_token,
            refresh_token=refresh_token,
            token_expires_at=token_expires_at,
        )

        session["user_id"] = user_id
        session["username"] = username
        session["discriminator"] = discriminator
        session["avatar"] = avatar_url

        return redirect(url_for("dashboard"))
    except urllib.error.HTTPError as he:
        error_body = he.read().decode("utf-8")
        logger.error("OAuth HTTP error %d: %s - %s", he.code, he.reason, error_body)
        return redirect(url_for("index"))
    except Exception as e:
        logger.error("OAuth error: %s", str(e))
        return redirect(url_for("index"))


@app.route("/api/user")
def get_user():
    """Get current user information."""
    if not session.get("user_token") and not session.get("user_id"):
        return jsonify({"success": True, "logged_in": False})

    try:
        user_id = session.get("user_id")

        if not all([session.get("username"), session.get("avatar")]) and user_id:
            user_data = db.get_discord_user(user_id)
            if user_data:
                session["user_token"] = user_data.get("access_token")
                session["username"] = user_data.get("username")
                session["discriminator"] = user_data.get("discriminator")
                session["avatar"] = user_data.get("avatar_url")
            else:
                session.clear()
                return jsonify({"success": True, "logged_in": False})

        return jsonify(
            {
                "success": True,
                "logged_in": True,
                "user_id": session.get("user_id"),
                "username": session.get("username"),
                "discriminator": session.get("discriminator"),
                "avatar": session.get("avatar"),
            }
        )
    except Exception as e:
        logger.error("Error getting user info: %s", str(e))
        return jsonify(
            {"success": False, "error": "Could not retrieve user information"}
        )


@app.route("/api/servers")
@login_required
def get_servers():
    """Get list of servers where the user is an admin."""
    try:
        user_id = session.get("user_id")

        cached_servers = db.get_cached_servers(user_id)

        if cached_servers is None:
            guild_headers = {
                "Authorization": f"Bearer {session['user_token']}",
                "User-Agent": OAUTH_USER_AGENT,
                "Accept": "application/json",
            }

            guild_request = urllib.request.Request(
                "https://discord.com/api/users/@me/guilds",
                headers=guild_headers,
            )

            with urllib.request.urlopen(guild_request) as response:
                guilds = json.loads(response.read().decode("utf-8"))

            admin_guilds = []
            servers_to_cache = []

            for guild in guilds:
                permissions = int(guild.get("permissions", 0))
                if (permissions & 0x20) == 0x20:
                    guild_id = guild["id"]

                    icon_url = None
                    if guild.get("icon"):
                        icon_url = (
                            "https://cdn.discordapp.com/icons/"
                            f"{guild['id']}/{guild['icon']}.png"
                        )
                    else:
                        icon_url = "https://cdn.discordapp.com/embed/avatars/0.png"

                    servers_to_cache.append(
                        {
                            "id": guild_id,
                            "name": guild["name"],
                            "icon": icon_url,
                        }
                    )

            if servers_to_cache:
                db.store_cached_servers(user_id, servers_to_cache)

            cached_servers = servers_to_cache

        admin_guilds = []
        for server in cached_servers:
            guild_id = server["id"]
            has_bot = False

            if bot.is_ready():
                try:
                    bot_guild = bot.get_guild(int(guild_id))
                    if bot_guild is None and hasattr(bot, "get_mutual_guilds"):
                        mutual_guilds = [g for g in bot.guilds if str(g.id) == guild_id]
                        has_bot = len(mutual_guilds) > 0
                    else:
                        has_bot = bot_guild is not None
                except Exception as e:
                    logger.error("Error checking bot guild membership: %s", str(e))
                    has_bot = False

            admin_guilds.append(
                {
                    "id": guild_id,
                    "name": server["name"],
                    "icon": server["icon"],
                    "has_bot": has_bot,
                }
            )

        return jsonify(
            {
                "success": True,
                "servers": admin_guilds,
                "client_id": CLIENT_ID,
                "redirect_uri": request.host_url + "auth",
            }
        )
    except urllib.error.HTTPError as e:
        logger.error("HTTP error getting servers: %s - %s", e.code, e.reason)
        return jsonify({"success": False, "error": "Could not retrieve server list"})
    except Exception as e:
        logger.error("Error getting servers: %s", str(e))
        return jsonify({"success": False, "error": "Could not retrieve server list"})


@app.route("/verify")
def verify():
    """Render the verification page."""
    return Response(
        render_template("verify.html", site_key=HCAPTCHA_SITE_KEY),
        headers={"Cache-Control": "public, max-age=31536000"},
    )


@app.route("/api/verify-tokens", methods=["GET"])
@rate_limit(1)
def verify_tokens():
    """Verify the verification and user tokens."""
    verification_id = request.args.get("verification_id")
    user_token = request.args.get("token")

    if not verification_id or not user_token:
        return jsonify({"success": False, "error": "Missing verification parameters"})

    user_info = db.validate_user_token(user_token)
    if not user_info:
        return jsonify(
            {"success": False, "error": "Invalid or expired verification token"}
        )

    verification = db.get_verification(verification_id)
    if not verification:
        return jsonify({"success": False, "error": "Invalid verification request"})

    avatar_url = user_info.get(
        "avatar_url", "https://cdn.discordapp.com/embed/avatars/0.png"
    )

    username = user_info.get("username", "Unknown User")
    discriminator = user_info.get("discriminator", "0")

    return jsonify(
        {
            "success": True,
            "verification_id": verification_id,
            "user_token": user_token,
            "member_id": user_info.get("member_id"),
            "username": username,
            "discriminator": discriminator,
            "avatar_url": avatar_url,
        }
    )


@app.route("/api/complete-verification", methods=["POST"])
@rate_limit(2)
def complete_verification():
    """Complete the verification process after hCaptcha is solved."""
    data = request.json

    verification_id = data.get("verification_id")
    user_token = data.get("user_token")
    captcha_response = data.get("captcha_response")

    if not verification_id or not user_token or not captcha_response:
        return jsonify({"success": False, "error": "Missing required fields"})

    if not verify_hcaptcha(captcha_response):
        return jsonify({"success": False, "error": "CAPTCHA verification failed"})

    user_info = db.validate_user_token(user_token)
    if not user_info:
        return jsonify(
            {"success": False, "error": "Invalid or expired verification token"}
        )

    try:
        member_id = user_info.get("member_id")

        db.mark_verification_complete(verification_id, member_id)
        db.remove_user_token(user_token)

        return jsonify(
            {
                "success": True,
                "message": "Verification successful! You can now return to Discord.",
            }
        )
    except Exception as e:
        logger.error("Error completing verification: %s", str(e))
        return jsonify(
            {"success": False, "error": "An error occurred during verification"}
        )


@app.route("/logout")
def logout():
    """Log the user out and clear session data."""
    user_id = session.get("user_id")

    if user_id:
        db.delete_discord_user(user_id)

    session.clear()
    return redirect(url_for("index"))


@app.route("/api/guild/<guild_id>")
@login_required
def get_guild_info(guild_id):
    """Get information about a specific guild."""
    try:
        user_id = session.get("user_id")
        user_token = session.get("user_token")

        # Verify user has access to this guild
        guild_headers = {
            "Authorization": f"Bearer {user_token}",
            "User-Agent": OAUTH_USER_AGENT,
            "Accept": "application/json",
        }

        # Check if user has access to this guild
        cached_servers = db.get_cached_servers(user_id) or []  # Ensure it's not None
        server_ids = (
            [server["id"] for server in cached_servers] if cached_servers else []
        )

        if guild_id not in server_ids:
            try:
                guild_request = urllib.request.Request(
                    "https://discord.com/api/users/@me/guilds",
                    headers=guild_headers,
                )

                with urllib.request.urlopen(guild_request) as response:
                    guilds = json.loads(response.read().decode("utf-8"))

                if not any(guild["id"] == guild_id for guild in guilds):
                    return (
                        jsonify(
                            {
                                "success": False,
                                "error": "You don't have access to this guild",
                            }
                        ),
                        403,
                    )

                # Verify the user has admin permissions
                for guild in guilds:
                    if guild["id"] == guild_id:
                        permissions = int(guild.get("permissions", 0))
                        is_admin = (
                            permissions & 0x20
                        ) == 0x20  # Check for ADMINISTRATOR permission

                        if not is_admin:
                            return (
                                jsonify(
                                    {
                                        "success": False,
                                        "error": "You need administrator permissions",
                                    }
                                ),
                                403,
                            )
            except Exception as e:
                logger.error("Error checking guild access: %s", str(e))
                return (
                    jsonify(
                        {"success": False, "error": "Error validating guild access"}
                    ),
                    500,
                )

        # Check if bot is in guild
        bot_in_guild = False
        guild_channels = []
        guild_roles = []

        if bot.is_ready():
            try:
                guild = bot.get_guild(int(guild_id))
                if guild:
                    bot_in_guild = True

                    # Get text channels
                    for channel in guild.text_channels:
                        guild_channels.append(
                            {
                                "id": str(channel.id),
                                "name": channel.name,
                                "position": channel.position,
                            }
                        )

                    # Sort channels by position
                    guild_channels.sort(key=lambda c: c["position"])

                    # Get roles that bot can manage
                    bot_member = guild.get_member(bot.user.id)
                    if bot_member:  # Check if bot_member exists
                        for role in guild.roles:
                            # Skip @everyone role and roles higher than bot's highest role
                            if not role.is_default() and role < bot_member.top_role:
                                guild_roles.append(
                                    {
                                        "id": str(role.id),
                                        "name": role.name,
                                        "color": str(role.color),
                                        "position": role.position,
                                    }
                                )

                    # Sort roles by position (highest position first)
                    guild_roles.sort(key=lambda r: r["position"], reverse=True)
            except Exception as e:
                logger.error("Error getting guild data: %s", str(e))
                # Continue execution to return what we have

        if not bot_in_guild:
            return jsonify(
                {
                    "success": True,
                    "bot_in_guild": False,
                    "guild_id": guild_id,
                    "invite_url": f"https://discord.com/oauth2/authorize?client_id={CLIENT_ID}&permissions=2415919104&response_type=code&redirect_uri={REDIRECT_URI}&scope=guilds+identify+bot&guild_id={guild_id}",
                }
            )

        # Get verification messages
        verifications = []
        try:
            conn = db.get_connection()
            cursor = conn.cursor()

            cursor.execute(
                """
                SELECT * FROM verification_messages 
                WHERE guild_id = ?
                """,
                (guild_id,),
            )

            verification_rows = cursor.fetchall()

            for row in verification_rows:
                verifications.append(
                    {
                        "id": row["id"],
                        "channel_id": row["channel_id"],
                        "role_id": row["role_id"],
                        "captcha_type": (
                            row["captcha_type"]
                            if "captcha_type" in row.keys()
                            else "hcaptcha"
                        ),
                        "embed_title": (
                            row["embed_title"]
                            if "embed_title" in row.keys()
                            else "Verification Required"
                        ),
                        "embed_description": (
                            row["embed_description"]
                            if "embed_description" in row.keys()
                            else ""
                        ),
                        "embed_color": (
                            row["embed_color"]
                            if "embed_color" in row.keys()
                            else "blue"
                        ),
                        "embed_footer": (
                            row["embed_footer"] if "embed_footer" in row.keys() else ""
                        ),
                        "created_at": row["created_at"],
                    }
                )

            conn.close()
        except Exception as e:
            logger.error("Error getting verifications: %s", str(e))
            # Continue execution to return what we have

        return jsonify(
            {
                "success": True,
                "bot_in_guild": True,
                "guild_id": guild_id,
                "channels": guild_channels,
                "roles": guild_roles,
                "verifications": verifications,
            }
        )

    except Exception as e:
        logger.error("Error getting guild info: %s", str(e))
        return (
            jsonify(
                {"success": False, "error": "Could not retrieve guild information"}
            ),
            500,
        )


@app.route("/api/guild/<guild_id>/verification", methods=["POST"])
@login_required
def create_guild_verification(guild_id):
    """Create or update a verification message."""
    try:
        data = request.json

        channel_id = data.get("channel_id")
        role_id = data.get("role_id")
        captcha_type = data.get("captcha_type", "hcaptcha")
        embed_title = data.get("embed_title", "Verification Required")
        embed_description = data.get("embed_description")
        embed_color = data.get("embed_color", "blue")
        embed_footer = data.get("embed_footer")

        if not channel_id or not role_id:
            return jsonify({"success": False, "error": "Missing required fields"}), 400

        # Verify user has admin access to this guild
        user_id = session.get("user_id")
        cached_servers = db.get_cached_servers(user_id)
        has_access = False

        if cached_servers and any(
            server["id"] == guild_id for server in cached_servers
        ):
            has_access = True

        if not has_access:
            return (
                jsonify(
                    {"success": False, "error": "You don't have access to this guild"}
                ),
                403,
            )

        # Verify bot is in guild and can access channel and role
        if not bot.is_ready():
            return jsonify({"success": False, "error": "Bot is not connected"}), 503

        guild = bot.get_guild(int(guild_id))
        if not guild:
            return jsonify({"success": False, "error": "Bot is not in this guild"}), 404

        channel = guild.get_channel(int(channel_id))
        if not channel or not isinstance(channel, discord.TextChannel):
            return jsonify({"success": False, "error": "Invalid channel"}), 400

        role = guild.get_role(int(role_id))
        if not role:
            return jsonify({"success": False, "error": "Invalid role"}), 400

        bot_member = guild.get_member(bot.user.id)
        if bot_member.top_role <= role:
            return (
                jsonify(
                    {
                        "success": False,
                        "error": f"Bot cannot assign the {role.name} role due to role hierarchy",
                    }
                ),
                400,
            )

        # Create or update verification
        verification_id = db.create_verification(
            guild_id,
            channel_id,
            role_id,
            captcha_type,
            embed_title,
            embed_description,
            embed_color,
            embed_footer,
        )

        # Get the verification data to use for the message
        verification = db.get_verification(verification_id)

        # Default description if none provided
        default_description = (
            f"To access the rest of the server, please verify you're not a robot.\n"
            f"Click the button below to start the verification process.\n\n"
            f"Once verified, you'll be given the {role.mention} role."
        )

        description = verification.get("embed_description") or default_description
        title = verification.get("embed_title") or "Verification Required"
        color_name = verification.get("embed_color") or "blue"
        footer = verification.get("embed_footer")

        # Convert color name to discord.Color
        color_map = {
            "blue": discord.Color.blue(),
            "red": discord.Color.red(),
            "green": discord.Color.green(),
            "gold": discord.Color.gold(),
            "purple": discord.Color.purple(),
            "orange": discord.Color.orange(),
            "blurple": discord.Color.blurple(),
        }

        color = color_map.get(color_name.lower(), discord.Color.blue())

        embed = discord.Embed(
            title=title,
            description=description,
            color=color,
        )

        if footer:
            embed.set_footer(text=footer)

        # Send the verification message using the bot's function
        from src.bot import send_verification_message

        # Create embed data dictionary
        embed_data = {
            "title": title,
            "description": description,
            "color": color_name,
            "footer": footer,
        }

        # Call the function directly using the bot's event loop
        try:
            future = asyncio.run_coroutine_threadsafe(
                send_verification_message(channel_id, embed_data, bot.loop), bot.loop
            )
            success, result = future.result(timeout=15)
            
            if not success:
                logger.error(f"Bot reported error: {result}")
                return (
                    jsonify(
                        {
                            "success": False,
                            "error": f"Failed to send verification message: {result}",
                        }
                    ),
                    400,  # Using 400 instead of 500 since this isn't a server error
                )
                
            # If we're here, the message was sent successfully
            logger.info(f"Successfully created verification with message ID: {result}")
        except Exception as e:
            logger.error(f"Error executing send_verification_message: {str(e)}")
            return (
                jsonify(
                    {
                        "success": False,
                        "error": f"Error sending verification message: {str(e)}",
                    }
                ),
                500,
            )

        return jsonify({"success": True, "verification_id": verification_id})

    except Exception as e:
        logger.error("Error creating verification: %s", str(e))
        return (
            jsonify({"success": False, "error": "Could not create verification"}),
            500,
        )


@app.route("/api/guild/<guild_id>/verification/<verification_id>", methods=["PUT"])
@login_required
def update_guild_verification(guild_id, verification_id):
    """Update an existing verification message."""
    try:
        data = request.json

        role_id = data.get("role_id")
        captcha_type = data.get("captcha_type")
        embed_title = data.get("embed_title")
        embed_description = data.get("embed_description")
        embed_color = data.get("embed_color")
        embed_footer = data.get("embed_footer")
        update_message = data.get("update_message", False)

        # Get existing verification
        verification = db.get_verification(verification_id)
        if not verification:
            return jsonify({"success": False, "error": "Verification not found"}), 404

        # Verify this verification belongs to this guild
        if verification["guild_id"] != guild_id:
            return (
                jsonify(
                    {
                        "success": False,
                        "error": "Verification doesn't belong to this guild",
                    }
                ),
                403,
            )

        # Verify user has admin access to this guild
        user_id = session.get("user_id")
        cached_servers = db.get_cached_servers(user_id)
        has_access = False

        if cached_servers and any(
            server["id"] == guild_id for server in cached_servers
        ):
            has_access = True

        if not has_access:
            return (
                jsonify(
                    {"success": False, "error": "You don't have access to this guild"}
                ),
                403,
            )

        # Check bot access
        if not bot.is_ready():
            return jsonify({"success": False, "error": "Bot is not connected"}), 503

        guild = bot.get_guild(int(guild_id))
        if not guild:
            return jsonify({"success": False, "error": "Bot is not in this guild"}), 404

        # If role is being updated, verify the new role
        channel_id = verification["channel_id"]
        channel = guild.get_channel(int(channel_id))

        if not channel or not isinstance(channel, discord.TextChannel):
            return jsonify({"success": False, "error": "Channel no longer exists"}), 400

        if role_id:
            role = guild.get_role(int(role_id))
            if not role:
                return jsonify({"success": False, "error": "Invalid role"}), 400

            bot_member = guild.get_member(bot.user.id)
            if bot_member.top_role <= role:
                return (
                    jsonify(
                        {
                            "success": False,
                            "error": f"Bot cannot assign the {role.name} role due to role hierarchy",
                        }
                    ),
                    400,
                )
        else:
            # Use existing role ID if none provided
            role_id = verification["role_id"]
            role = guild.get_role(int(role_id))

        # Update verification in database
        conn = db.get_connection()
        cursor = conn.cursor()

        # Only update fields that were provided
        update_fields = []
        update_values = []

        if role_id:
            update_fields.append("role_id = ?")
            update_values.append(role_id)

        if captcha_type:
            update_fields.append("captcha_type = ?")
            update_values.append(captcha_type)

        if embed_title:
            update_fields.append("embed_title = ?")
            update_values.append(embed_title)

        if embed_description is not None:  # Allow empty string
            update_fields.append("embed_description = ?")
            update_values.append(embed_description)

        if embed_color:
            update_fields.append("embed_color = ?")
            update_values.append(embed_color)

        if embed_footer is not None:  # Allow empty string
            update_fields.append("embed_footer = ?")
            update_values.append(embed_footer)

        if update_fields:
            update_sql = f"UPDATE verification_messages SET {', '.join(update_fields)} WHERE id = ?"
            update_values.append(verification_id)

            cursor.execute(update_sql, update_values)
            conn.commit()

        conn.close()

        # If requested, update the message in Discord
        if update_message:
            # Get updated verification data
            updated_verification = db.get_verification(verification_id)

            # Default description if none provided
            default_description = (
                f"To access the rest of the server, please verify you're not a robot.\n"
                f"Click the button below to start the verification process.\n\n"
                f"Once verified, you'll be given the {role.mention} role."
            )

            description = (
                updated_verification.get("embed_description") or default_description
            )
            title = updated_verification.get("embed_title") or "Verification Required"
            color_name = updated_verification.get("embed_color") or "blue"
            footer = updated_verification.get("embed_footer")

            # Create embed data dictionary
            embed_data = {
                "title": title,
                "description": description,
                "color": color_name,
                "footer": footer,
            }

            # Call the function directly using the bot's event loop
            success, result = asyncio.run_coroutine_threadsafe(
                send_verification_message(channel_id, embed_data, bot.loop), bot.loop
            ).result(timeout=15)

            if not success:
                return (
                    jsonify(
                        {
                            "success": False,
                            "error": f"Failed to send verification message: {result}",
                        }
                    ),
                    400,  # Using 400 instead of 500 since this isn't a server error
                )
                
            # If we're here, the message was sent successfully
            logger.info(f"Successfully updated verification with message ID: {result}")

        return jsonify({"success": True, "verification_id": verification_id})

    except Exception as e:
        logger.error("Error updating verification: %s", str(e))
        return (
            jsonify({"success": False, "error": "Could not update verification"}),
            500,
        )


@app.route("/api/guild/<guild_id>/verification/<verification_id>", methods=["DELETE"])
@login_required
def delete_guild_verification(guild_id, verification_id):
    """Delete a verification message."""
    try:
        # Get existing verification
        verification = db.get_verification(verification_id)
        if not verification:
            return jsonify({"success": False, "error": "Verification not found"}), 404

        # Verify this verification belongs to this guild
        if verification["guild_id"] != guild_id:
            return (
                jsonify(
                    {
                        "success": False,
                        "error": "Verification doesn't belong to this guild",
                    }
                ),
                403,
            )

        # Verify user has admin access to this guild
        user_id = session.get("user_id")
        cached_servers = db.get_cached_servers(user_id)
        has_access = False

        if cached_servers and any(
            server["id"] == guild_id for server in cached_servers
        ):
            has_access = True

        if not has_access:
            return (
                jsonify(
                    {"success": False, "error": "You don't have access to this guild"}
                ),
                403,
            )

        # Delete verification from database
        conn = db.get_connection()
        cursor = conn.cursor()
        
        # First delete any completed verifications associated with this verification message
        cursor.execute(
            "DELETE FROM verification_completions WHERE verification_id = ?",
            (verification_id,)
        )
        
        # Then delete the verification message itself
        cursor.execute(
            "DELETE FROM verification_messages WHERE id = ?",
            (verification_id,)
        )
        
        conn.commit()
        conn.close()

        logger.info(f"Successfully deleted verification message {verification_id}")
        return jsonify({"success": True})

    except Exception as e:
        logger.error("Error deleting verification: %s", str(e))
        return (
            jsonify({"success": False, "error": "Could not delete verification"}),
            500,
        )


async def run_app():
    """
    Run the Flask application asynchronously.

    Returns:
        None
    """

    def run_flask():
        app.run(host="0.0.0.0", port=5000, debug=False)

    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, run_flask)
