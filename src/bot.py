import os
import time
import random
import asyncio
from io import BytesIO
from typing import Optional
from urllib.parse import quote

import discord
from PIL import Image
from discord import app_commands
from discord.ext import commands

from src.logger import log
from src.discordauth import User
from src.files import CURRENT_DIRECTORY_PATH
from src.database import get_database_decrypted
from src.utils import (
    load_dotenv, generate_secure_string, cache_with_ttl,
    http_request
)


load_dotenv()
DISCORD_TOKEN = os.getenv("DISCORD_TOKEN")
CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
REDIRECT_URI = quote("https://" + os.getenv("HOSTNAME", ""))


intents = discord.Intents.default()
intents.members = True

bot = commands.Bot(command_prefix = "/", intents = intents)


def has_role(role_id: int, guild_id: Optional[int] = None,
             member_id: Optional[int] = None, guild: Optional[discord.Guild] = None,
             member: Optional[discord.Member] = None) -> bool:
    """
    Checks if a member has a specific role in a Discord guild.

    This function determines whether a member is already verified by checking
    if they possess the specified role. It can retrieve the member either by
    providing a member object directly or by using the guild ID and member ID.

    Args:
        role_id (int): The ID of the role to check for verification.
        guild_id (Optional[int]): The ID of the guild where the member resides.
                                  Required if `guild` is not provided.
        member_id (Optional[int]): The ID of the member to check for the role.
                                   Required if `member` is not provided.
        guild (Optional[discord.Guild]): An optional Discord guild object.
                                          If provided, `guild_id` is not needed.
        member (Optional[discord.Member]): An optional Discord member object.
                                           If provided, `member_id` is not needed.

    Returns:
        bool: True if the member has the specified role, False otherwise.
    """

    if member is None:
        if guild is None:
            guild = bot.get_guild(guild_id)
        member = guild.get_member(member_id)

    return member.get_role(role_id) is not None


def verify_user(guild_id: int, role_id: int, user: User, was_verified: bool = False) -> bool:
    """
    Verifies a user by assigning them a specific role in a Discord guild.

    Args:
        guild_id (int): The ID of the Discord guild where the user is to be verified.
        role_id (int): The ID of the role to assign to the user upon verification.
        user (User): The User object representing the user to be verified.
        was_verified (bool): A flag indicating whether the user was previously verified.
                             Defaults to False.

    Returns:
        bool: True if the user was successfully verified (role assigned or already verified),
              False if the verification process failed.
    """

    guild = bot.get_guild(guild_id)
    if guild:
        role = guild.get_role(role_id)
        member = guild.get_member(user.user_id)

        if member and role:
            if not was_verified and has_role(role_id, member = member):
                return True

            bot.loop.create_task(member.add_roles(role))
            return True

    return False


@cache_with_ttl(10)
async def guilds() -> int:
    """
    Returns the approximate number of guilds the bot is
    currently in, with a cache TTL of 10 seconds.

    Returns:
        int: The number of guilds the bot is currently in.
    """

    return len(bot.guilds)


@cache_with_ttl(5)
async def check_latency() -> int:
    """
    Measures the latency of a request to the Discord API.

    Returns:
        int: The latency of the API request in milliseconds.
    """

    start_time = time.perf_counter()
    http_request("https://discord.com/api", is_json = True)
    end_time = time.perf_counter()

    return round((end_time - start_time) * 1000)


@bot.tree.command(name = "ping", description = "View the latency of the bot")
async def ping(interaction: discord.Interaction) -> None:
    """
    Handles the "ping" command to check bot latency.
    
    Args:
        interaction (discord.Interaction): The interaction object for the command.

    Returns:
        None: Sends a message with the bot's API latency in milliseconds.
    """

    api_latency = await check_latency()

    await interaction.response.send_message(f"**🏓 Pong!**\nAPI: {api_latency}ms")


@bot.tree.command(name="add", description="Set up verification for a role")
@app_commands.describe(role="Role to assign after verification")
async def add(interaction: discord.Interaction, role: discord.Role) -> None:
    """
    Handles the "add" command to enable verification for a specified role.
    
    Args:
        interaction (discord.Interaction): The interaction object for the command.
        role (discord.Role): The role to assign upon successful verification.
        
    Returns:
        None: Sends an embedded message with a verification link if the user is an admin.
        Otherwise, sends an ephemeral error message.
    """

    if not interaction.user.guild_permissions.administrator:
        await interaction.response.send_message(
            "You do not have permission to use this command.", ephemeral=True
        )
        return

    if role == interaction.guild.default_role:
        await interaction.response.send_message(
            "The @everyone role is not permitted.", ephemeral=True
        )
        return

    states = get_database_decrypted("states", None)

    state = None
    value = (interaction.guild_id, role.id)
    if (state_key := states.get_key(value)) is not None:
        state = state_key
    else:
        while not state or states.exists(state):
            state = generate_secure_string(20)

    states[state] = (interaction.guild_id, role.id)

    embed = discord.Embed(
        title = "🤖Beep beop Boop?",
        description = "Click the button below to verify you are not a robot.",
        color = discord.Color.blue()
    )
    view = discord.ui.View()
    button = discord.ui.Button(
        label = "Verify",
        url = (
            f"https://discord.com/oauth2/authorize?client_id={CLIENT_ID}&redirect_uri="
            f"{REDIRECT_URI}%2Fauth&response_type=code&scope=identify&state={state}"
        )
    )
    view.add_item(button)

    await interaction.response.send_message(embed=embed, view=view)


async def update_banner() -> None:
    """
    Periodically updates the bot's banner with randomized image placements.

    Returns:
        None
    """

    small_image = Image.open(os.path.join(CURRENT_DIRECTORY_PATH, "src", "assets", "icon.png"))
    small_image = small_image.resize((50, 50), Image.LANCZOS)

    while True:
        image_positions = []

        def overlaps(x: int, y: int, width: int, height: int) -> bool:
            """
            Checks if a new image placement overlaps with existing placements.
            
            Parameters:
                x, y (int): Coordinates of the top-left corner of the new image.
                width, height (int): Width and height of the new image.

            Returns:
                bool: True if overlapping, False otherwise.
            """

            for (px, py, pw, ph) in image_positions:
                if (x < px + pw and x + width > px and y < py + ph and y + height > py):
                    return True

            return False

        banner = Image.new("RGB", (600, 240), "#181818")
        for _ in range(13):
            max_attempts = 100
            for _ in range(max_attempts):
                rotated_image = small_image.rotate(random.uniform(0, 360), expand=True)
                image_box = rotated_image.getbbox()

                max_x = 600 - image_box[2]
                max_y = 240 - image_box[3]

                if max_x <= 0 or max_y <= 0:
                    continue

                x = random.randint(0, max_x)
                y = random.randint(0, max_y)

                if not overlaps(x, y, image_box[2], image_box[3]):
                    banner.paste(rotated_image, (x, y), rotated_image)
                    image_positions.append((x, y, image_box[2], image_box[3]))
                    break

        with BytesIO() as banner_buffer:
            banner.save(banner_buffer, format="PNG")
            banner_buffer.seek(0)

            try:
                await bot.user.edit(banner=banner_buffer.read())
                log("Banner updated.")
            except Exception:
                log("Error updating banner.", level = 4)

        await asyncio.sleep(3600) # 1 hour


@bot.event
async def on_ready() -> None:
    """
    Event handler triggered when the bot is ready.
    
    Returns:
        None
    """

    bot.loop.create_task(update_banner())

    log(f"Logged in as {bot.user}.", level = 2)

    try:
        synced = await bot.tree.sync()
        log(f"Synced {len(synced)} commands.")
    except Exception:
        log("Error syncing commands.", level = 4)


async def run_bot() -> None:
    """
    Starts the bot using the specified Discord token.

    Returns:
        None
    """

    await bot.start(DISCORD_TOKEN)


if __name__ == "__main__":
    asyncio.run(run_bot())
