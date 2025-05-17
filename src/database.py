import sqlite3
import time
from typing import Optional, List

from src.utils import generate_random_id

DATABASE_PATH = "verification.db"


class Database:
    """
    A class for interacting with the database.

    Attributes:
        db_path: The path to the database file

    Methods:
        get_connection: Get a database connection
        initialize_db: Initialize the database with required tables if they don't exist
        create_verification: Create a new verification entry or update existing one
        get_verification_by_channel: Get a verification entry by guild_id and channel_id
        get_verification: Get a verification entry by its ID
        create_user_token: Create a new user token or return existing one if valid
        validate_user_token: Validate a user token and return the user information if valid
        check_rate_limit: Check if a member is rate limited for a specific action
        mark_verification_complete: Mark a verification as complete after successful verification
        get_pending_verifications: Get pending verifications to process
        mark_verification_processed: Mark a verification as processed and clean up user tokens
        remove_user_token: Remove a user token from the database
        get_guild_count: Get the count of unique guilds in the database
        delete_discord_user: Delete a Discord user's data from the database
        store_cached_servers: Store cached server information for a user
        get_cached_servers: Get cached server information for a user if still valid
    """

    def __init__(self, db_path: str = DATABASE_PATH):
        self.db_path = db_path
        self.initialize_db()

    def get_connection(self) -> sqlite3.Connection:
        """Get a database connection."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def initialize_db(self) -> None:
        """Initialize the database with required tables if they don't exist."""
        conn = self.get_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
        CREATE TABLE IF NOT EXISTS verification_messages (
            id TEXT PRIMARY KEY,
            guild_id TEXT NOT NULL,
            channel_id TEXT NOT NULL,
            role_id TEXT NOT NULL,
            captcha_type TEXT DEFAULT 'hcaptcha',
            embed_title TEXT DEFAULT 'Verification Required',
            embed_description TEXT,
            embed_color TEXT DEFAULT 'blue',
            embed_footer TEXT,
            created_at INTEGER NOT NULL
        )
        """
        )

        cursor.execute(
            """
        CREATE TABLE IF NOT EXISTS user_tokens (
            token TEXT PRIMARY KEY,
            member_id TEXT NOT NULL,
            verification_id TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            username TEXT,
            discriminator TEXT,
            avatar_url TEXT,
            FOREIGN KEY (verification_id) REFERENCES verification_messages(id)
        )
        """
        )

        cursor.execute(
            """
        CREATE TABLE IF NOT EXISTS rate_limits (
            member_id TEXT NOT NULL,
            action_type TEXT NOT NULL,
            timestamp INTEGER NOT NULL,
            PRIMARY KEY (member_id, action_type)
        )
        """
        )

        cursor.execute(
            """
        CREATE TABLE IF NOT EXISTS completed_verifications (
            id TEXT PRIMARY KEY,
            verification_id TEXT NOT NULL,
            member_id TEXT NOT NULL,
            completed_at INTEGER NOT NULL,
            processed BOOLEAN NOT NULL DEFAULT 0,
            FOREIGN KEY (verification_id) REFERENCES verification_messages(id)
        )
        """
        )

        cursor.execute(
            """
        CREATE TABLE IF NOT EXISTS discord_users (
            id TEXT PRIMARY KEY,
            username TEXT NOT NULL,
            discriminator TEXT,
            avatar_url TEXT,
            access_token TEXT NOT NULL,
            refresh_token TEXT,
            token_expires_at INTEGER,
            created_at INTEGER NOT NULL,
            last_login INTEGER NOT NULL
        )
        """
        )

        cursor.execute(
            """
        CREATE TABLE IF NOT EXISTS cached_servers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT NOT NULL,
            guild_id TEXT NOT NULL,
            guild_name TEXT NOT NULL,
            guild_icon TEXT,
            last_updated INTEGER NOT NULL,
            UNIQUE(user_id, guild_id)
        )
        """
        )

        conn.commit()
        conn.close()

    def create_verification(
        self,
        guild_id: str,
        channel_id: str,
        role_id: str,
        captcha_type: str = "hcaptcha",
        embed_title: str = "Verification Required",
        embed_description: str = None,
        embed_color: str = "blue",
        embed_footer: str = None,
    ) -> str:
        """
        Create a new verification entry or update existing one if
        there's already one in the channel.

        Args:
            guild_id: The Discord guild ID
            channel_id: The Discord channel ID
            role_id: The Discord role ID
            captcha_type: Type of captcha to use (default: hcaptcha)
            embed_title: Title for the embed message
            embed_description: Description for the embed message
            embed_color: Color for the embed message
            embed_footer: Footer for the embed message

        Returns:
            str: The verification ID
        """
        conn = self.get_connection()
        cursor = conn.cursor()

        cursor.execute(
            "SELECT id FROM verification_messages WHERE guild_id = ? AND channel_id = ?",
            (guild_id, channel_id),
        )
        existing = cursor.fetchone()

        verification_id = None
        if existing:
            verification_id = existing["id"]
            cursor.execute(
                """UPDATE verification_messages SET 
                role_id = ?, 
                captcha_type = ?,
                embed_title = ?,
                embed_description = ?,
                embed_color = ?,
                embed_footer = ?,
                created_at = ? 
                WHERE id = ?""",
                (
                    role_id,
                    captcha_type,
                    embed_title,
                    embed_description,
                    embed_color,
                    embed_footer,
                    int(time.time()),
                    verification_id,
                ),
            )
        else:
            verification_id = generate_random_id()
            cursor.execute(
                """INSERT INTO verification_messages 
                (id, guild_id, channel_id, role_id, captcha_type, 
                embed_title, embed_description, embed_color, embed_footer, created_at) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    verification_id,
                    guild_id,
                    channel_id,
                    role_id,
                    captcha_type,
                    embed_title,
                    embed_description,
                    embed_color,
                    embed_footer,
                    int(time.time()),
                ),
            )

        conn.commit()
        conn.close()
        return verification_id

    def get_verification_by_channel(
        self, guild_id: str, channel_id: str
    ) -> Optional[dict]:
        """Get a verification entry by guild_id and channel_id."""
        conn = self.get_connection()
        cursor = conn.cursor()

        cursor.execute(
            "SELECT * FROM verification_messages WHERE guild_id = ? AND channel_id = ?",
            (guild_id, channel_id),
        )
        result = cursor.fetchone()

        conn.close()
        return dict(result) if result else None

    def get_verification(self, verification_id: str) -> Optional[dict]:
        """Get a verification entry by its ID."""
        conn = self.get_connection()
        cursor = conn.cursor()

        cursor.execute(
            "SELECT * FROM verification_messages WHERE id = ?", (verification_id,)
        )
        result = cursor.fetchone()

        conn.close()
        return dict(result) if result else None

    def create_user_token(
        self,
        member_id: str,
        verification_id: str,
        username: str = None,
        discriminator: str = None,
        avatar_url: str = None,
    ) -> str:
        """
        Create a new user token or return existing one if valid.

        Args:
            member_id: Discord member ID
            verification_id: Verification ID
            username: Discord username
            discriminator: Discord discriminator (if available)
            avatar_url: URL to the user's avatar

        Returns:
            str: The user token
        """
        conn = self.get_connection()
        cursor = conn.cursor()

        current_time = int(time.time())
        token_validity = 20 * 60

        cursor.execute(
            """SELECT token FROM user_tokens 
            WHERE member_id = ? AND verification_id = ? AND created_at > ?""",
            (member_id, verification_id, current_time - token_validity),
        )
        existing = cursor.fetchone()

        if existing:
            token = existing["token"]
            if (
                username is not None
                or discriminator is not None
                or avatar_url is not None
            ):
                cursor.execute(
                    """UPDATE user_tokens 
                    SET username = ?, discriminator = ?, avatar_url = ? WHERE token = ?""",
                    (username, discriminator, avatar_url, token),
                )
                conn.commit()
        else:
            token = generate_random_id(16)
            cursor.execute(
                """INSERT INTO user_tokens 
                (token, member_id, verification_id, created_at, username, discriminator, avatar_url) 
                VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    token,
                    member_id,
                    verification_id,
                    current_time,
                    username,
                    discriminator,
                    avatar_url,
                ),
            )

        conn.commit()
        conn.close()
        return token

    def validate_user_token(self, token: str) -> Optional[dict]:
        """
        Validate a user token and return the user information if valid.

        Returns:
            Optional[dict]: User information if the token is valid, None otherwise
        """
        conn = self.get_connection()
        cursor = conn.cursor()

        current_time = int(time.time())
        token_validity = 20 * 60

        cursor.execute(
            """SELECT member_id, username, discriminator, avatar_url 
            FROM user_tokens WHERE token = ? AND created_at > ?""",
            (token, current_time - token_validity),
        )
        result = cursor.fetchone()

        conn.close()
        return dict(result) if result else None

    def check_rate_limit(
        self, member_id: str, action_type: str, limit_seconds: int = 60
    ) -> bool:
        """
        Check if a member is rate limited for a specific action.

        Returns:
            bool: True if rate limited, False otherwise
        """
        conn = self.get_connection()
        cursor = conn.cursor()

        current_time = int(time.time())

        cursor.execute(
            "SELECT timestamp FROM rate_limits WHERE member_id = ? AND action_type = ?",
            (member_id, action_type),
        )
        result = cursor.fetchone()

        if result and (current_time - result["timestamp"]) < limit_seconds:
            conn.close()
            return True

        if result:
            cursor.execute(
                """UPDATE rate_limits 
                SET timestamp = ? WHERE member_id = ? AND action_type = ?""",
                (current_time, member_id, action_type),
            )
        else:
            cursor.execute(
                """INSERT INTO rate_limits 
                (member_id, action_type, timestamp) VALUES (?, ?, ?)""",
                (member_id, action_type, current_time),
            )

        conn.commit()
        conn.close()
        return False

    def mark_verification_complete(self, verification_id: str, member_id: str) -> str:
        """
        Mark a verification as complete after successful hCaptcha verification.

        Args:
            verification_id: The verification ID
            member_id: The member ID

        Returns:
            str: The ID of the completion record
        """
        conn = self.get_connection()
        cursor = conn.cursor()

        completion_id = generate_random_id()
        current_time = int(time.time())

        cursor.execute(
            """
            INSERT INTO completed_verifications 
            (id, verification_id, member_id, completed_at, processed) 
            VALUES (?, ?, ?, ?, 0)
            """,
            (completion_id, verification_id, member_id, current_time),
        )

        conn.commit()
        conn.close()
        return completion_id

    def get_pending_verifications(self, limit: int = 10) -> List[dict]:
        """
        Get pending verifications to process.

        Args:
            limit: Maximum number of verifications to return

        Returns:
            List[dict]: List of pending verifications
        """
        conn = self.get_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT cv.id, cv.verification_id, cv.member_id, cv.completed_at, 
                   vm.guild_id, vm.role_id 
            FROM completed_verifications cv
            JOIN verification_messages vm ON cv.verification_id = vm.id
            WHERE cv.processed = 0
            ORDER BY cv.completed_at ASC
            LIMIT ?
            """,
            (limit,),
        )

        results = cursor.fetchall()
        conn.close()

        return [dict(r) for r in results] if results else []

    def mark_verification_processed(
        self, completion_id: str, member_id: str, verification_id: str
    ) -> None:
        """
        Mark a verification as processed after the role has been assigned and clean up user tokens.

        Args:
            completion_id: The ID of the completion record
            member_id: The member ID
            verification_id: The verification ID
        """
        conn = self.get_connection()
        cursor = conn.cursor()

        cursor.execute(
            "UPDATE completed_verifications SET processed = 1 WHERE id = ?",
            (completion_id,),
        )

        cursor.execute(
            "DELETE FROM user_tokens WHERE member_id = ? AND verification_id = ?",
            (member_id, verification_id),
        )

        cursor.execute(
            """DELETE FROM rate_limits 
            WHERE member_id = ? AND action_type IN ('verify_button', 'role_assignment')""",
            (member_id,),
        )

        conn.commit()
        conn.close()

    def remove_user_token(self, token: str) -> None:
        """
        Remove a user token from the database.

        Args:
            token: The token to remove
        """
        conn = self.get_connection()
        cursor = conn.cursor()

        cursor.execute(
            "DELETE FROM user_tokens WHERE token = ?",
            (token,),
        )

        conn.commit()
        conn.close()

    def store_discord_user(
        self,
        user_id: str,
        username: str,
        discriminator: str,
        avatar_url: str,
        access_token: str,
        refresh_token: str = None,
        token_expires_at: int = None,
    ) -> None:
        """
        Store Discord user information in the database.

        Args:
            user_id: Discord user ID
            username: Discord username
            discriminator: Discord discriminator
            avatar_url: Discord avatar URL
            access_token: OAuth access token
            refresh_token: OAuth refresh token (optional)
            token_expires_at: Token expiration timestamp (optional)
        """
        conn = self.get_connection()
        cursor = conn.cursor()

        current_time = int(time.time())

        cursor.execute(
            "SELECT id FROM discord_users WHERE id = ?",
            (user_id,),
        )
        existing = cursor.fetchone()

        if existing:
            cursor.execute(
                """UPDATE discord_users SET 
                username = ?, 
                discriminator = ?, 
                avatar_url = ?, 
                access_token = ?, 
                refresh_token = ?, 
                token_expires_at = ?,
                last_login = ?
                WHERE id = ?""",
                (
                    username,
                    discriminator,
                    avatar_url,
                    access_token,
                    refresh_token,
                    token_expires_at,
                    current_time,
                    user_id,
                ),
            )
        else:
            cursor.execute(
                """INSERT INTO discord_users 
                (
                    id, 
                    username, 
                    discriminator, 
                    avatar_url, 
                    access_token, 
                    refresh_token, 
                    token_expires_at, 
                    created_at, 
                    last_login
                )
                VALUES (
                    ?, 
                    ?, 
                    ?, 
                    ?, 
                    ?, 
                    ?, 
                    ?, 
                    ?, 
                    ?
                )""",
                (
                    user_id,
                    username,
                    discriminator,
                    avatar_url,
                    access_token,
                    refresh_token,
                    token_expires_at,
                    current_time,
                    current_time,
                ),
            )

        conn.commit()
        conn.close()

    def get_discord_user(self, user_id: str) -> Optional[dict]:
        """
        Get Discord user information from the database.

        Args:
            user_id: Discord user ID

        Returns:
            Optional[dict]: User information if found, None otherwise
        """
        conn = self.get_connection()
        cursor = conn.cursor()

        cursor.execute(
            "SELECT * FROM discord_users WHERE id = ?",
            (user_id,),
        )
        result = cursor.fetchone()

        conn.close()
        return dict(result) if result else None

    def delete_discord_user(self, user_id: str) -> bool:
        """
        Delete a Discord user's data from the database.

        Args:
            user_id: Discord user ID

        Returns:
            bool: True if user was deleted, False otherwise
        """
        conn = self.get_connection()
        cursor = conn.cursor()

        try:
            cursor.execute(
                "DELETE FROM discord_users WHERE id = ?",
                (user_id,),
            )
            deleted = cursor.rowcount > 0
            conn.commit()
            return deleted
        except Exception:
            return False
        finally:
            conn.close()

    def store_cached_servers(self, user_id: str, servers: list) -> None:
        """
        Store cached server information for a user.

        Args:
            user_id: Discord user ID
            servers: List of server information dictionaries with id, name, icon
        """
        conn = self.get_connection()
        cursor = conn.cursor()
        current_time = int(time.time())

        try:
            conn.execute("BEGIN TRANSACTION")
            cursor.execute("DELETE FROM cached_servers WHERE user_id = ?", (user_id,))

            for server in servers:
                cursor.execute(
                    """INSERT INTO cached_servers 
                    (user_id, guild_id, guild_name, guild_icon, last_updated) 
                    VALUES (?, ?, ?, ?, ?)""",
                    (
                        user_id,
                        server["id"],
                        server["name"],
                        server.get("icon"),
                        current_time,
                    ),
                )

            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def get_cached_servers(
        self, user_id: str, cache_ttl: int = 43200
    ) -> Optional[List[dict]]:
        """
        Get cached server information for a user if still valid.

        Args:
            user_id: Discord user ID
            cache_ttl: Cache time-to-live in seconds (default 12 hours)

        Returns:
            Optional[List[dict]]: List of cached servers or None if cache is invalid
        """
        conn = self.get_connection()
        cursor = conn.cursor()
        current_time = int(time.time())
        cache_valid_after = current_time - cache_ttl

        cursor.execute(
            """SELECT guild_id, guild_name, guild_icon, last_updated
            FROM cached_servers 
            WHERE user_id = ? AND last_updated > ?
            ORDER BY guild_name""",
            (user_id, cache_valid_after),
        )

        results = cursor.fetchall()
        conn.close()

        if not results:
            return None

        if results[0]["last_updated"] <= cache_valid_after:
            return None

        servers = []
        for row in results:
            servers.append(
                {
                    "id": row["guild_id"],
                    "name": row["guild_name"],
                    "icon": row["guild_icon"],
                }
            )

        return servers
