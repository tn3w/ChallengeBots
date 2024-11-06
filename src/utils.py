import os
import time
import secrets
from functools import wraps


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
                    value = [item.strip() for item in value.split(",")] if "," in value else value.strip()
                    os.environ[key.strip()] = value.strip()

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
