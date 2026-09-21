import json
import secrets
import sqlite3
import time
from contextlib import closing

DATABASE_PATH = "verification.db"
TOKEN_LIFETIME = 20 * 60
SERVER_CACHE_LIFETIME = 12 * 60 * 60

SCHEMA = """
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
);
CREATE TABLE IF NOT EXISTS user_tokens (
    token TEXT PRIMARY KEY,
    member_id TEXT NOT NULL,
    verification_id TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    username TEXT,
    discriminator TEXT,
    avatar_url TEXT
);
CREATE TABLE IF NOT EXISTS rate_limits (
    member_id TEXT NOT NULL,
    action_type TEXT NOT NULL,
    timestamp INTEGER NOT NULL,
    PRIMARY KEY (member_id, action_type)
);
CREATE TABLE IF NOT EXISTS server_cache (
    user_id TEXT PRIMARY KEY,
    servers TEXT NOT NULL,
    updated_at INTEGER NOT NULL
);
"""

EDITABLE_FIELDS = (
    "role_id",
    "captcha_type",
    "embed_title",
    "embed_description",
    "embed_color",
    "embed_footer",
    "message_id",
)


def connect() -> sqlite3.Connection:
    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def execute(query: str, parameters=()) -> list[dict]:
    with closing(connect()) as connection, connection:
        return [dict(row) for row in connection.execute(query, parameters)]


def initialize() -> None:
    with closing(connect()) as connection, connection:
        connection.executescript(SCHEMA)
        columns = {
            row[1]
            for row in connection.execute("PRAGMA table_info(verification_messages)")
        }
        if "message_id" not in columns:
            connection.execute(
                "ALTER TABLE verification_messages ADD COLUMN message_id TEXT"
            )


def first(rows: list[dict]) -> dict | None:
    return rows[0] if rows else None


def get_verification(verification_id: str) -> dict | None:
    return first(
        execute("SELECT * FROM verification_messages WHERE id = ?", (verification_id,))
    )


def get_verification_by_channel(guild_id: str, channel_id: str) -> dict | None:
    query = "SELECT * FROM verification_messages WHERE guild_id = ? AND channel_id = ?"
    return first(execute(query, (guild_id, channel_id)))


def list_verifications(guild_id: str) -> list[dict]:
    query = "SELECT * FROM verification_messages WHERE guild_id = ? ORDER BY created_at"
    return execute(query, (guild_id,))


def save_verification(guild_id: str, channel_id: str, **fields) -> str:
    existing = get_verification_by_channel(guild_id, channel_id)
    if existing:
        update_verification(existing["id"], **fields)
        return existing["id"]

    verification_id = secrets.token_urlsafe(12)
    execute(
        """INSERT INTO verification_messages
        (id, guild_id, channel_id, role_id, created_at) VALUES (?, ?, ?, ?, ?)""",
        (verification_id, guild_id, channel_id, fields["role_id"], int(time.time())),
    )
    update_verification(verification_id, **fields)
    return verification_id


def update_verification(verification_id: str, **fields) -> None:
    changes = {name: value for name, value in fields.items() if name in EDITABLE_FIELDS}
    if not changes:
        return
    assignments = ", ".join(f"{name} = ?" for name in changes)
    query = f"UPDATE verification_messages SET {assignments} WHERE id = ?"
    execute(query, (*changes.values(), verification_id))


def delete_verification(verification_id: str) -> None:
    execute("DELETE FROM user_tokens WHERE verification_id = ?", (verification_id,))
    execute("DELETE FROM verification_messages WHERE id = ?", (verification_id,))


def create_user_token(member_id: str, verification_id: str, **profile) -> str:
    execute(
        "DELETE FROM user_tokens WHERE member_id = ? AND verification_id = ?",
        (member_id, verification_id),
    )
    token = secrets.token_urlsafe(16)
    execute(
        """INSERT INTO user_tokens (token, member_id, verification_id, created_at,
        username, discriminator, avatar_url) VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (
            token,
            member_id,
            verification_id,
            int(time.time()),
            profile.get("username"),
            profile.get("discriminator"),
            profile.get("avatar_url"),
        ),
    )
    return token


def get_user_token(token: str) -> dict | None:
    query = "SELECT * FROM user_tokens WHERE token = ? AND created_at > ?"
    return first(execute(query, (token, int(time.time()) - TOKEN_LIFETIME)))


def remove_user_token(token: str) -> None:
    execute("DELETE FROM user_tokens WHERE token = ?", (token,))


def is_rate_limited(key: str, action: str, seconds: int) -> bool:
    now = int(time.time())
    query = "SELECT timestamp FROM rate_limits WHERE member_id = ? AND action_type = ?"
    previous = first(execute(query, (key, action)))
    if previous and now - previous["timestamp"] < seconds:
        return True
    execute(
        """INSERT OR REPLACE INTO rate_limits (member_id, action_type, timestamp)
        VALUES (?, ?, ?)""",
        (key, action, now),
    )
    return False


def get_cached_servers(user_id: str) -> list[dict] | None:
    query = "SELECT servers FROM server_cache WHERE user_id = ? AND updated_at > ?"
    row = first(execute(query, (user_id, int(time.time()) - SERVER_CACHE_LIFETIME)))
    return json.loads(row["servers"]) if row else None


def cache_servers(user_id: str, servers: list[dict]) -> None:
    execute(
        """INSERT OR REPLACE INTO server_cache (user_id, servers, updated_at)
        VALUES (?, ?, ?)""",
        (user_id, json.dumps(servers), int(time.time())),
    )


def clear_servers(user_id: str) -> None:
    execute("DELETE FROM server_cache WHERE user_id = ?", (user_id,))
