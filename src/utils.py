import os
import time
import json
import socket
import secrets
import http.client
import urllib.error
import urllib.request
from functools import wraps
from urllib.parse import urlencode
from typing import Optional, Callable, Any

from src.files import CURRENT_DIRECTORY_PATH, read


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


def load_dotenv(file_name: str = ".env") -> None:
    """
    Load environment variables from a .env file into the system environment.

    Args:
        file_name (str): Name of the env file. Defaults to ".env" in the current directory.
    """

    file_path = os.path.join(CURRENT_DIRECTORY_PATH, file_name)
    dotenv_content: str = read(file_path, default = "")

    for line in dotenv_content.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            key, value = line.split("=", 1)

            os.environ[key.strip()] = value


def cache_with_ttl(ttl: int) -> Callable:
    """
    Caches the result of an asynchronous function with a given TTL.

    Args:
        ttl (int): The TTL in seconds.

    Returns:
        Callable: The decorated function.
    """

    def decorator(func: Callable) -> Callable:
        """
        Internal decorator function.

        Args:
            func (Callable): The function to decorate.

        Returns:
            Callable: The decorated function.
        """

        cache = {}

        @wraps(func)
        async def wrapper(*args, **kwargs) -> Any:
            """
            Internal wrapper function.

            Args:
                *args: The positional arguments to pass to the function.
                **kwargs: The keyword arguments to pass to the function.
            """

            key = (args, frozenset(kwargs.items()))
            current_time = time.time()

            # Check if result is in cache and not expired
            if key in cache:
                result, timestamp = cache[key]
                if current_time - timestamp < ttl:
                    return result

                # If expired, remove from cache
                del cache[key]

            # Await the function's result and store it in cache with the current timestamp
            result = await func(*args, **kwargs)
            cache[key] = (result, current_time)

            return result

        return wrapper

    return decorator


def http_request(url: str, method: str = "GET", timeout: int = 2,
                 is_json: bool = False, default: Optional[Any] = None,
                 headers: Optional[dict] = None, data: Optional[dict] = None) -> Optional[Any]:
    """
    Sends an HTTP request to the specified URL and returns the response content.

    Args:
        url (str): The URL to which the request is sent.
        method (str, optional): The HTTP method to use for the request. 
        timeout (int, optional): The maximum time (in seconds) to wait 
            for a response.
        is_json (bool, optional): If True, the response content is parsed 
            as JSON and returned as a Python object. 
            If False, the raw response content is 
            returned as bytes.
        default (Optional[Any], optional): The value to return if an 
            exception occurs during the request.
        headers (Optional[dict], optional): Additional headers to include 
            in the request.
        data (Optional[dict], optional): The data to send in the request body. 

    Returns:
        Optional[Any]: The response content, either as a parsed JSON 
                        object or as bytes. Returns None if an exception 
                        occurs during the request.
    """

    default_headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
                      " (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.3"
    }

    if headers:
        default_headers.update(headers)

    if data:
        data = urlencode(data).encode('utf-8')

    try:
        req = urllib.request.Request(
            url,
            headers = default_headers,
            method = method,
            data = data
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
