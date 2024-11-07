import os
import re
import pickle
from typing import Optional, Tuple

from src.logger import log
from src.database import get_database
from src.crypto.symmetric import AES256
from src.files import DATA_DIRECTORY_PATH, read, write
from src.utils import generate_secure_string, http_request


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


def is_valid_oauth_code(code: str) -> bool:
    """
    Checks if the provided code is a valid Discord OAuth authorization code.

    Args:
        code (str): The authorization code to validate.

    Returns:
        bool: True if the code is valid, False otherwise.
    """

    if len(code) != 30:
        return False

    pattern = r'^[A-Za-z0-9]{30}$'

    return bool(re.match(pattern, code))


def get_access_token(client_id: str, client_secret: str,
                     redirect_uri: str, code: str) -> Optional[str]:
    """
    Obtains an access token from Discord's OAuth2 API using the authorization code flow.

    Args:
        client_id (str): The client ID of the application.
        client_secret (str): The client secret of the application.
        redirect_uri (str): The redirect URI registered with the application.
        code (str): The authorization code received from the OAuth2 flow.

    Returns:
        Optional[str]: The access token if successful, None otherwise.
    """

    data = {
        "client_id": client_id,
        "client_secret": client_secret,
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri
    }

    url = "https://discord.com/api/oauth2/token"
    headers = {"Content-Type": "application/x-www-form-urlencoded"}

    response = http_request(
        url, "POST", is_json = True,
        headers = headers, data = data
    )

    if not response or not isinstance(response, dict):
        return None

    return response.get("access_token")


def get_user_info(access_token: str) -> Optional["User"]:
    """
    Retrieves user information from Discord's API using the provided access token.

    Args:
        access_token (str): The access token obtained from the OAuth2 flow.

    Returns:
        Optional[User]: A "User" object representing an Discord user.
    """

    url = "https://discord.com/api/users/@me"
    headers = {"Authorization": f"Bearer {access_token}"}

    response = http_request(url, is_json = True, headers = headers)

    if not response or not isinstance(response, dict):
        return None

    return User(response)


class User:
    """
    Represents a Discord user.

    Attributes:
        user_id (int): The unique identifier for the user.
        user_name (str): The username of the user.
        discriminator (int): The discriminator of the user, used to differentiate users
                             with the same username.
        avatar_url (str): The URL of the user's avatar. If no custom avatar is set,
                          a default avatar URL is generated.
    """

    def __init__(self, user_info: dict) -> None:
        """
        Initializes an Discord user.

        Args:
            user_info (dict): A dictionary containing user information, which must include
                the user's ID, username, and discriminator. The avatar field is optional.
        """

        user_id = int(user_info.get("id", 0))
        user_name = user_info.get("username")
        avatar = user_info.get("avatar")
        discriminator = int(user_info.get("discriminator", 0))

        self.user_info = {
            "id": user_id,
            "username": user_name,
            "avatar": avatar,
            "discriminator": discriminator
        }

        if avatar is None:
            default_avatar_index = discriminator % 5
            self.avatar_url = f"https://cdn.discordapp.com/embed/avatars/{default_avatar_index}.png"
        else:
            self.avatar_url = f"https://cdn.discordapp.com/avatars/{user_id}/{avatar}.webp"

        self.user_id = user_id
        self.user_name = user_name
        self.discriminator = discriminator


def create_session(user: User, access_token: str) -> str:
    """
    Creates a secure session for the user and generates a session token.

    Args:
        user (User): The user object containing the user's information.
        access_token (str): A token obtained from the authentication provider,
            used to encrypt the user's session data.

    Returns:
        str: An encrypted session token representing the user's session.
    """

    user_info = user.user_info
    dumped_user_info = pickle.dumps(user_info)
    encrypted_user_info = AES256(access_token, serialization = "bytes").encrypt(dumped_user_info)

    sessions = get_database("sessions", 604800) # 7 days
    sessions[str(user.user_id)] = encrypted_user_info

    session_token = SESSION_AES.encrypt(str(user.user_id) + "/" + access_token)
    return session_token


def get_session(session_token: str) -> Tuple[Optional[User], Optional[str]]:
    """
    Retrieves and decrypts the user session based on the provided session token.

    Args:
        session_token (str): The session token used to locate and decrypt
            the user's session data.

    Returns:
        Tuple[Optional[User], Optional[str]]: A tuple containing the user object
            and access token if valid, or (None, None) if the session retrieval fails.
    """

    try:
        decrypted_session_token = SESSION_AES.decrypt(session_token).decode("utf-8")
        user_id, access_token = decrypted_session_token.split("/", 1)
    except Exception as exc:
        log(exc, level = 4)
        return (None, None)

    sessions = get_database("sessions", 604800) # 7 days
    encrypted_user_info = sessions[user_id]
    try:
        decrypted_user_info = AES256(
            access_token, serialization = "bytes"
        ).decrypt(encrypted_user_info)

        loaded_user_info = pickle.loads(decrypted_user_info)
    except Exception as exc:
        log(exc, level = 4)
        return (None, None)

    user = User(loaded_user_info)

    return user, access_token
