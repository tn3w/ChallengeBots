import logging
import os

import discord
from discord import app_commands, ui

from src import database

logger = logging.getLogger(__name__)

COLORS = {
    "blue": discord.Color.blue(),
    "red": discord.Color.red(),
    "green": discord.Color.green(),
    "gold": discord.Color.gold(),
    "purple": discord.Color.purple(),
    "orange": discord.Color.orange(),
    "blurple": discord.Color.blurple(),
}


class ChallengeBot(discord.Client):
    def __init__(self):
        super().__init__(intents=discord.Intents.default())
        self.tree = app_commands.CommandTree(self)

    async def setup_hook(self):
        self.add_view(VerificationView())
        await self.tree.sync()


bot = ChallengeBot()


def build_embed(verification: dict, role: discord.Role) -> discord.Embed:
    default_description = (
        "To access the rest of the server, please verify you're not a robot.\n"
        "Click the button below to start the verification process.\n\n"
        f"Once verified, you'll be given the {role.mention} role."
    )
    color = COLORS.get(
        (verification.get("embed_color") or "blue").lower(), COLORS["blue"]
    )
    embed = discord.Embed(
        title=verification.get("embed_title") or "Verification Required",
        description=verification.get("embed_description") or default_description,
        color=color,
    )
    if verification.get("embed_footer"):
        embed.set_footer(text=verification["embed_footer"])
    return embed


def role_problem(guild: discord.Guild, role: discord.Role) -> str | None:
    if role.is_default():
        return "The @everyone role cannot be used for verification."
    if not guild.me.guild_permissions.manage_roles:
        return "The bot needs the 'Manage Roles' permission."
    if guild.me.top_role <= role:
        return f"Move the bot's role above {role.name} so it can assign it."
    return None


async def publish_verification(verification_id: str) -> str | None:
    verification = database.get_verification(verification_id)
    guild = bot.get_guild(int(verification["guild_id"]))
    channel = guild and guild.get_channel(int(verification["channel_id"]))
    role = guild and guild.get_role(int(verification["role_id"]))
    if not isinstance(channel, discord.TextChannel) or role is None:
        return "Channel or role no longer exists."

    embed = build_embed(verification, role)
    try:
        if verification.get("message_id"):
            message = channel.get_partial_message(int(verification["message_id"]))
            await message.edit(embed=embed, view=VerificationView())
            return None
    except discord.NotFound:
        pass

    try:
        message = await channel.send(embed=embed, view=VerificationView())
    except discord.Forbidden:
        return "The bot cannot send messages in that channel."
    database.update_verification(verification_id, message_id=str(message.id))
    return None


async def grant_role(verification: dict, member_id: str) -> str | None:
    guild = bot.get_guild(int(verification["guild_id"]))
    role = guild and guild.get_role(int(verification["role_id"]))
    if role is None:
        return "The verification role no longer exists."
    try:
        member = await guild.fetch_member(int(member_id))
        await member.add_roles(role, reason="Passed ChallengeBots verification")
    except discord.NotFound:
        return "You are no longer a member of this server."
    except discord.Forbidden:
        return "The bot is not allowed to assign the role."

    try:
        await member.send(f"You have been verified in **{guild.name}**.")
    except discord.HTTPException:
        pass
    return None


class VerificationView(ui.View):
    def __init__(self):
        super().__init__(timeout=None)

    @ui.button(
        label="Verify", style=discord.ButtonStyle.primary, custom_id="verify_button"
    )
    async def verify(self, interaction: discord.Interaction, _button: ui.Button):
        await interaction.response.send_message(
            start_verification(interaction), ephemeral=True
        )


def start_verification(interaction: discord.Interaction) -> str:
    user = interaction.user
    verification = database.get_verification_by_channel(
        str(interaction.guild_id), str(interaction.channel_id)
    )
    if not verification:
        return "This verification is no longer set up. Please contact an administrator."
    if any(str(role.id) == verification["role_id"] for role in user.roles):
        return "You are already verified."
    if database.is_rate_limited(str(user.id), "verify_button", 2):
        return "You're clicking too fast. Please wait a moment."

    token = database.create_user_token(
        str(user.id),
        verification["id"],
        username=user.name,
        discriminator=user.discriminator,
        avatar_url=user.display_avatar.url,
    )
    base_url = os.getenv("BASE_URL", "http://localhost:5000").rstrip("/")
    link = f"{base_url}/verify#{verification['id']}.{token}"
    return f"Verify here: {link}\nThis link is valid for 20 minutes."


@bot.tree.command(name="ping", description="Show the bot latency")
async def ping(interaction: discord.Interaction):
    latency = round(bot.latency * 1000)
    await interaction.response.send_message(f"Pong! {latency} ms", ephemeral=True)


@bot.tree.command(name="create", description="Create a verification message here")
@app_commands.describe(role="The role to assign to verified users")
@app_commands.default_permissions(administrator=True)
@app_commands.guild_only()
async def create(interaction: discord.Interaction, role: discord.Role):
    problem = role_problem(interaction.guild, role)
    if problem:
        await interaction.response.send_message(problem, ephemeral=True)
        return

    verification_id = database.save_verification(
        str(interaction.guild_id), str(interaction.channel_id), role_id=str(role.id)
    )
    await interaction.response.defer(ephemeral=True)
    error = await publish_verification(verification_id)
    await interaction.followup.send(
        error or "Verification message created.", ephemeral=True
    )
