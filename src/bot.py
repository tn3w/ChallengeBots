import os
import traceback
import logging
import asyncio

import discord
from discord import app_commands, ui
from discord.ext import commands, tasks

from src.utils import load_dotenv
from src.database import Database

logger = logging.getLogger(__name__)

load_dotenv()
DISCORD_TOKEN = os.getenv("DISCORD_TOKEN")
CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")

bot = commands.Bot(command_prefix="/", intents=discord.Intents.default())


class VerifyButton(ui.Button):
    """
    A button for the verification process.
    """

    def __init__(self):
        super().__init__(
            label="Verify", style=discord.ButtonStyle.primary, custom_id="verify_button"
        )

    async def callback(self, interaction: discord.Interaction):
        try:
            db = Database()

            guild_id = str(interaction.guild_id)
            channel_id = str(interaction.channel_id)

            verification_data = db.get_verification_by_channel(guild_id, channel_id)
            if not verification_data:
                await interaction.response.send_message(
                    "Error: Could not find verification information for this channel. "
                    "Please contact an administrator.",
                    ephemeral=True,
                )
                return

            verification_id = verification_data["id"]

            if "role_id" in verification_data and verification_data["role_id"]:
                role_id = int(verification_data["role_id"])
                member = interaction.user
                if any(role.id == role_id for role in member.roles):
                    await interaction.response.send_message(
                        "You already have the role associated with this verification.",
                        ephemeral=True,
                    )
                    return

            if db.check_rate_limit(str(interaction.user.id), "verify_button", 2):
                return await interaction.response.send_message(
                    "You're clicking too fast. Please wait a moment before trying again.",
                    ephemeral=True,
                )

            username = interaction.user.name
            discriminator = (
                interaction.user.discriminator
                if hasattr(interaction.user, "discriminator")
                else "0"
            )

            if interaction.user.avatar:
                avatar_url = interaction.user.avatar.url
            elif (
                hasattr(interaction.user, "default_avatar")
                and interaction.user.default_avatar
            ):
                avatar_url = interaction.user.default_avatar.url
            else:
                avatar_url = (
                    "https://cdn.discordapp.com/embed/avatars/"
                    f"{int(discriminator) % 5}.png"
                )

            user_token = db.create_user_token(
                str(interaction.user.id),
                verification_id,
                username,
                discriminator,
                avatar_url,
            )

            verification_url = (
                f"http://localhost:5000/verify#{verification_id}.{user_token}"
            )

            await interaction.response.send_message(
                f"Click this link to verify you're not a robot: {verification_url}\n"
                f"This link is valid for 20 minutes.",
                ephemeral=True,
            )
        except Exception as e:
            logger.error(
                "Error in VerifyButton callback: %s\n%s", str(e), traceback.format_exc()
            )
            try:
                await interaction.response.send_message(
                    "An error occurred while processing your verification. "
                    "Please try again later.",
                    ephemeral=True,
                )
            except discord.errors.InteractionResponded:
                pass


class VerificationView(ui.View):
    """
    A view for the verification button.
    """

    def __init__(self):
        super().__init__(timeout=None)
        self.add_item(VerifyButton())


@bot.tree.command(name="ping", description="View the latency of the bot")
async def ping(interaction: discord.Interaction) -> None:
    """
    Handles the "ping" command to check bot latency.

    Args:
        interaction (discord.Interaction): The interaction object for the command.

    Returns:
        None: Sends a message with the bot's API latency in milliseconds.
    """

    await interaction.response.send_message(
        f":ping_pong: Pong! Bot latency: {round(bot.latency * 1000)}ms", ephemeral=True
    )


@bot.tree.command(
    name="create", description="Create a verification message in the current channel"
)
@app_commands.describe(role="The role to assign to verified users")
async def create(interaction: discord.Interaction, role: discord.Role) -> None:
    """
    Creates a verification message in the current channel with a button for users to verify.

    Args:
        interaction (discord.Interaction): The interaction object for the command.
        role (discord.Role): The role to assign to users who verify.

    Returns:
        None: Sends a verification message in the channel.
    """
    if not interaction.user.guild_permissions.administrator:
        return await interaction.response.send_message(
            "You need administrator permissions to use this command.", ephemeral=True
        )

    if role.is_default():
        return await interaction.response.send_message(
            "You cannot use the @everyone role for verification. "
            "Please select a specific role.",
            ephemeral=True,
        )

    bot_member = interaction.guild.get_member(bot.user.id)
    if not bot_member.guild_permissions.manage_roles:
        return await interaction.response.send_message(
            "I don't have the 'Manage Roles' permission in this server. "
            "Please give me this permission and try again.",
            ephemeral=True,
        )

    if bot_member.top_role <= role:
        return await interaction.response.send_message(
            f"I cannot assign the {role.name} role because it is higher than or equal to "
            f"my highest role. Please move my role above the {role.name} "
            "role in the server settings.",
            ephemeral=True,
        )

    channel = interaction.channel

    db = Database()

    try:
        verification_id = db.create_verification(
            str(channel.guild.id), str(channel.id), str(role.id)
        )

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

        view = VerificationView()
        await interaction.response.send_message(embed=embed, view=view)
    except Exception as e:
        await interaction.followup.send(f"An error occurred: {str(e)}", ephemeral=True)


@tasks.loop(seconds=5)
async def process_pending_verifications():
    """
    Process pending verifications from the database.
    This task runs every 5 seconds to check for new verifications.
    """
    if not bot.is_ready():
        return

    db = Database()
    pending = db.get_pending_verifications(limit=10)

    for verification in pending:
        try:
            verification_id = verification["verification_id"]
            member_id = verification["member_id"]
            completion_id = verification["id"]

            guild = bot.get_guild(int(verification["guild_id"]))
            if not guild:
                db.mark_verification_processed(
                    completion_id, member_id, verification_id
                )
                continue

            try:
                member = await guild.fetch_member(int(member_id))
            except discord.NotFound:
                db.mark_verification_processed(
                    completion_id, member_id, verification_id
                )
                continue

            role = guild.get_role(int(verification["role_id"]))
            if not role:
                db.mark_verification_processed(
                    completion_id, member_id, verification_id
                )
                continue

            await member.add_roles(
                role, reason="Verified through the verification system"
            )

            try:
                await member.send(
                    f"Verification Complete: You have been verified in **{guild.name}** "
                    f"and given the **{role.name}** role."
                )
            except (discord.Forbidden, discord.HTTPException):
                pass

            db.mark_verification_processed(completion_id, member_id, verification_id)

        except (discord.NotFound, discord.Forbidden, discord.HTTPException):
            continue


@bot.event
async def on_ready():
    """
    Event handler that is called when the bot is ready.
    """
    print(f"Logged in as {bot.user} (ID: {bot.user.id})")

    try:
        synced = await bot.tree.sync()
        print(f"Synced {len(synced)} command(s)")
    except Exception as e:
        print(f"Failed to sync commands: {e}")

    bot.add_view(VerificationView())

    if not process_pending_verifications.is_running():
        process_pending_verifications.start()

    print("Bot is ready!")


async def send_verification_message(channel_id, embed_data, loop=None):
    """
    Function to send a verification message to a specific channel.
    This function is designed to be called from the Flask app.
    
    Args:
        channel_id (str): The ID of the channel to send the message to
        embed_data (dict): Dictionary containing embed information
        loop (asyncio.AbstractEventLoop, optional): Event loop to use
        
    Returns:
        tuple: (success, message_id_or_error)
    """
    try:
        if not bot.is_ready():
            logger.error("Bot is not ready")
            return False, "Bot is not ready"
            
        channel = bot.get_channel(int(channel_id))
        if not channel:
            logger.error(f"Channel {channel_id} not found")
            return False, f"Channel {channel_id} not found"
        
        # Create embed from data
        color_map = {
            "blue": discord.Color.blue(),
            "red": discord.Color.red(),
            "green": discord.Color.green(),
            "gold": discord.Color.gold(),
            "purple": discord.Color.purple(),
            "orange": discord.Color.orange(),
            "blurple": discord.Color.blurple(),
        }
        
        color = color_map.get(
            embed_data.get("color", "blue").lower(), discord.Color.blue()
        )
        
        embed = discord.Embed(
            title=embed_data.get("title", "Verification Required"),
            description=embed_data.get(
                "description", "Click the button below to verify."
            ),
            color=color,
        )
        
        if "footer" in embed_data and embed_data["footer"]:
            embed.set_footer(text=embed_data["footer"])
        
        view = VerificationView()
        
        # If no loop is provided, use the bot's loop
        if loop is None:
            loop = bot.loop
            
        try:
            # Send the message using the bot's event loop
            future = asyncio.run_coroutine_threadsafe(
                channel.send(embed=embed, view=view), loop
            )
            
            # Wait for the result with a timeout
            message = future.result(timeout=10)
            logger.info(f"Successfully sent verification message to channel {channel_id}, message ID: {message.id}")
            return True, str(message.id)
        except asyncio.TimeoutError:
            logger.error("Timeout while sending message")
            return False, "Timeout while sending message"
        except Exception as e:
            logger.error(f"Error in run_coroutine_threadsafe: {str(e)}")
            return False, str(e)
        
    except Exception as e:
        logger.error(f"Error sending verification message: {str(e)}")
        return False, str(e)


async def run_bot():
    """
    Start the Discord bot.

    Returns:
        None
    """
    try:
        await bot.start(DISCORD_TOKEN)
    except KeyboardInterrupt:
        await bot.close()
    except Exception as e:
        print(f"Error starting bot: {str(e)}")
