import os
import time
import json
import socket
import secrets
import http.client
import urllib.error
import urllib.request
from functools import wraps
from typing import Final, Optional, Any


CURRENT_DIRECTORY_PATH: Final[str] = os.path.dirname(os.path.abspath(__file__)) \
    .replace("\\", "/").replace("//", "/").replace("src", "").replace("//", "/")


def generate_secure_string(length: int):
    """
    Generate a random string.

    Parameters:
        length (int): The length of the string to be generated.

    Returns:
        str: A randomly generated string of the specified length
            composed of the selected characters.
    """

    return "".join(
        secrets.choice("063456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
        for _ in range(length)
    )


def load_dotenv(filepath: str = ".env") -> None:
    """
    Load environment variables from a .env file into the system environment.

    Args:
        filepath (str): Path to the .env file. Defaults to ".env" in the current directory.
    """

    try:
        with open(filepath, "r", encoding = "utf-8") as file:
            for line in file:
                line = line.strip()
                if line and not line.startswith("#"):
                    key, value = line.split("=", 1)

                    os.environ[key.strip()] = value

    except FileNotFoundError:
        print(f"Warning: {filepath} file not found.")
    except ValueError:
        print(f"Warning: {filepath} has an invalid format.")


def cache_with_ttl(ttl: int) -> callable:
    """
    Caches the result of a function with a given TTL.

    Args:
        ttl (int): The TTL in seconds.

    Returns:
        callable: The decorated function.
    """

    def decorator(func: callable) -> callable:
        """
        Internal decorator function.

        Args:
            func (callable): The function to decorate.

        Returns:
            callable: The decorated function.
        """

        cache = {}

        @wraps(func)
        def wrapper(*args, **kwargs):
            """
            Internal wrapper function.

            Args:
                *args: The positional arguments to pass to the function.
                **kwargs: The keyword arguments to pass to the function.
            """

            key = (args, tuple(kwargs.items()))
            current_time = time.time()

            if key in cache:
                result, timestamp = cache[key]
                if current_time - timestamp < ttl:
                    return result

                del cache[key]

            result = func(*args, **kwargs)
            cache[key] = (result, current_time)

            return result

        return wrapper

    return decorator


def http_request(url: str, method: str = "GET", timeout: int = 2,
                 is_json: bool = False, default: Optional[Any] = None) -> Optional[Any]:
    """
    Sends an HTTP request to the specified URL and returns the response content.

    Args:
        url (str): The URL to which the request is sent.
        method (str, optional): The HTTP method to use for the request. 
                                Defaults to "GET".
        timeout (int, optional): The maximum time (in seconds) to wait 
                                 for a response. Defaults to 2 seconds.
        is_json (bool, optional): If True, the response content is parsed 
                                  as JSON and returned as a Python object. 
                                  If False, the raw response content is 
                                  returned as bytes. Defaults to False.
        default (Optional[Any], optional): The value to return if an 
                                            exception occurs during the 
                                            request. Defaults to None.

    Returns:
        Optional[Any]: The response content, either as a parsed JSON 
                        object or as bytes. Returns None if an exception 
                        occurs during the request.
    """

    try:
        req = urllib.request.Request(
            url, headers = {"User-Agent":
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
                " (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.3"
            }, method = method
        )

        with urllib.request.urlopen(req, timeout = timeout) as response:
            if response.getcode() != 200:
                return default

            content = response.read().decode("utf-8")

        if is_json:
            return json.loads(content)

        return content

    except (urllib.error.HTTPError, urllib.error.URLError, socket.timeout, TimeoutError,
            json.JSONDecodeError, http.client.RemoteDisconnected, UnicodeEncodeError,
            http.client.IncompleteRead, http.client.HTTPException, ConnectionResetError,
            ConnectionAbortedError, ConnectionRefusedError, ConnectionError):
        pass

    return default
