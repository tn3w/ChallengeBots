import os
import time
import pickle
from typing import Final, Optional, Tuple, Dict, Any

from src.crypto.hashing import SHA256
from src.crypto.symmetric import AES256
from src.files import PICKLE, DATA_DIRECTORY_PATH, delete


SHA: Final[SHA256] = SHA256(1000, salt_length = 8)
CUSTOM_EPOCH_OFFSET = int(time.mktime((2020, 1, 1, 0, 0, 0, 0, 0, 0)))

DATABASES: Dict[str, Tuple["Database", "DatabaseDecrypted"]] = {}


def get_database(name: str, ttl: int = 259200) -> "Database":
    """
    Retrieve an existing database instance by name or create a new one if it does not exist.

    Args:
        name (str): The name of the database.
        ttl (int): The time-to-live (TTL) in seconds for database entries.
            Defaults to 259200 (3 days).
    
    Returns:
        Database: The database instance associated with the specified name.
    """


    db = DATABASES.get(name)
    if db is not None:
        return db

    db = Database(name, DATA_DIRECTORY_PATH, ttl)
    DATABASES[name] = db
    return db


def get_database_decrypted(name: str, ttl: int = 259200) -> "DatabaseDecrypted":
    """
    Retrieve an decrypted database instance by name or create a new one if it does not exist.

    Args:
        name (str): The name of the database.
        ttl (int): The time-to-live (TTL) in seconds for database entries.
            Defaults to 259200 (3 days).
    
    Returns:
        Database: The database instance associated with the specified name.
    """

    full_name = name + "decrypted"

    db = DATABASES.get(full_name)
    if db is not None:
        return db

    db = DatabaseDecrypted(name, DATA_DIRECTORY_PATH, ttl)
    DATABASES[full_name] = db
    return db


def get_time() -> int:
    """
    Returns the current timestamp in seconds relative to the 2010 epoch.

    Returns:
        int: The current time in seconds from the 2010 epoch.
    """

    return int(time.time() - CUSTOM_EPOCH_OFFSET)


class DatabaseInterface(dict):
    """
    An interface for database types.
    """

    def __init__(self, file_name: str, dir_path: Optional[str] = None,
                 ttl: Optional[int] = 259200) -> None:
        """
        Initializes the Database object with specified settings.

        Args:
            file_name (str): The name of the file to store time data.
            dir_path (Optional[str]): The directory path to store time data.
            ttl (int): The time-to-live in seconds, after which time data
                will be removed. Defaults to 259200 (3 days).
        """

        if not file_name.endswith('.pkl'):
            file_name += '.pkl'

        if dir_path is None:
            dir_path = DATA_DIRECTORY_PATH

        self.file_path = os.path.join(dir_path, file_name)
        self.ttl = ttl


    def _load(self) -> dict:
        return PICKLE.load(self.file_path, {})


    def _load_and_clean(self) -> dict:
        data = self._load()

        if not data:
            return data

        cleaned_data = self._clean(data)
        if data != cleaned_data:
            self._dump(cleaned_data)

        return cleaned_data


    def _dump(self, data: dict) -> bool:
        if not data:
            return delete(self.file_path)

        return PICKLE.dump(data, self.file_path)


    def _clean(self, data: dict) -> bool:
        current_time = get_time()

        if not self.ttl:
            return data

        return {
            key: (value, timestamp)
            for key, (value, timestamp) in data.items()
            if current_time - timestamp <= self.ttl
        }


class Database(DatabaseInterface):
    """
    A dictionary-based database with time-to-live (TTL)
    """


    def _get_stored_key(self, key: str, data: Optional[dict] = None) -> Optional[str]:
        """
        Retrieves the actual stored key for a given input key.

        Args:
            key (str): The input key to look for.
            data (Optional[dict]): The cache data dictionary to search within.

        Returns:
            Optional[str]: The stored key if found, otherwise None.
        """

        if data is None:
            data = self._load_and_clean()

        for stored_key in data:
            if SHA.compare(key, stored_key):
                return stored_key

        return None


    def _get(self, key: str) -> Optional[Any]:
        """
        Retrieves the value and timestamp for a given key after loading and cleaning data.

        Args:
            key (str): The key to retrieve.

        Returns:
            Optional[Any]: The stored value if the key exists, otherwise None.
        """

        data = self._load_and_clean()
        stored_key = self._get_stored_key(key, data)

        return data.get(stored_key, None)


    def __getitem__(self, key: str) -> Optional[Any]:
        """
        Allows dictionary-style access to retrieve a value.

        Args:
            key (str): The key to retrieve.

        Returns:
            Optional[Any]: The value associated with the key, or None if not found.
        """

        return self.get(key)


    def __setitem__(self, key: str, value: Any) -> bool:
        """
        Allows dictionary-style access to set a value.

        Args:
            key (str): The key for the value to store.
            value (Any): The value to store.

        Returns:
            bool: True if the operation succeeded, otherwise False.
        """

        return self.set(key, value)


    def __delitem__(self, key: Any) -> bool:
        """
        Allows dictionary-style deletion of a key-value pair.

        Args:
            key (Any): The key to delete.

        Returns:
            bool: True if the key was successfully deleted, False if it was not found.
        """

        data = self._load_and_clean()
        stored_key = self._get_stored_key(key, data)

        try:
            del data[stored_key]
        except (KeyError, TypeError, NameError):
            return False

        return self._dump(data)


    def get(self, key: str) -> Optional[Any]:
        """
        Retrieves and decrypts (if necessary) the value associated with a given key.

        Args:
            key (str): The key to retrieve.

        Returns:
            Optional[Any]: The value if the key exists and is valid, otherwise None.
        """

        data = self._get(key)
        if not isinstance(data, tuple):
            return None

        value = data[0]

        decrypted_value = AES256(key).decrypt(value)
        loaded_value = pickle.loads(decrypted_value)

        return loaded_value


    def set(self, key: str, value: Any) -> bool:
        """
        Stores a value associated with a key, encrypting it.

        Args:
            key (str): The key for the value to store.
            value (Any): The value to store.

        Returns:
            bool: True if the operation succeeded, otherwise False.
        """

        current_time = get_time()

        hashed_key = None
        if (stored_key := self._get_stored_key(key)) is not None:
            hashed_key = stored_key
        else:
            hashed_key = SHA.hash(key)

        value_tuple = current_time
        if value is not None:
            dumped_value = pickle.dumps(value)
            encrypted_value = AES256(key).encrypt(dumped_value)

            value_tuple = (encrypted_value, current_time)

        data = self._load_and_clean()

        data[hashed_key] = value_tuple
        return self._dump(data)


    def exists(self, key: str) -> bool:
        """
        Checks if a key exists in the cache.

        Args:
            key (str): The key to check.

        Returns:
            bool: True if the key exists, otherwise False.
        """

        return self._get(key) is not None


class DatabaseDecrypted(DatabaseInterface):
    """
    A dictionary-based database with time-to-live (TTL).
    """


    def _get(self, key: str) -> Optional[Any]:
        """
        Retrieves the value and timestamp for a given key after loading and cleaning data.

        Args:
            key (str): The key to retrieve.

        Returns:
            Optional[Any]: The stored value if the key exists, otherwise None.
        """

        data = self._load_and_clean()
        return data.get(key, None)


    def __getitem__(self, key: str) -> Optional[Any]:
        """
        Allows dictionary-style access to retrieve a value.

        Args:
            key (str): The key to retrieve.

        Returns:
            Optional[Any]: The value associated with the key, or None if not found.
        """

        return self.get(key)


    def __setitem__(self, key: str, value: Any) -> bool:
        """
        Allows dictionary-style access to set a value.

        Args:
            key (str): The key for the value to store.
            value (Any): The value to store.

        Returns:
            bool: True if the operation succeeded, otherwise False.
        """

        return self.set(key, value)


    def __delitem__(self, key: Any) -> bool:
        """
        Allows dictionary-style deletion of a key-value pair.

        Args:
            key (Any): The key to delete.

        Returns:
            bool: True if the key was successfully deleted, False if it was not found.
        """

        data = self._load_and_clean()

        try:
            del data[key]
        except (KeyError, TypeError, NameError):
            return False

        return self._dump(data)


    def get(self, key: str) -> Optional[Any]:
        """
        Retrieves and decrypts (if necessary) the value associated with a given key.

        Args:
            key (str): The key to retrieve.

        Returns:
            Optional[Any]: The value if the key exists and is valid, otherwise None.
        """

        data = self._get(key)
        if not isinstance(data, tuple):
            return data

        return data[0]


    def set(self, key: str, value: Any) -> bool:
        """
        Stores a value associated with a key, encrypting it if anonymous storage is enabled.

        Args:
            key (str): The key for the value to store.
            value (Any): The value to store.

        Returns:
            bool: True if the operation succeeded, otherwise False.
        """

        data = self._load_and_clean()

        if value is None:
            data[key] = get_time()
        else:
            data[key] = (value, get_time())

        return self._dump(data)


    def exists(self, key: str) -> bool:
        """
        Checks if a key exists in the cache.

        Args:
            key (str): The key to check.

        Returns:
            bool: True if the key exists, otherwise False.
        """

        return self._get(key) is not None


    def get_key(self, value: Any) -> Optional[str]:
        """
        Retrieves the key associated with a given value from the internal data structure.

        Args:
            value (Any): The value for which to find the corresponding key.

        Returns:
            Optional[str]: The key associated with the given value if found, None otherwise.
        """

        data = self._load_and_clean()
        for key, data_tuple in data.items():
            if isinstance(data_tuple, int):
                continue

            data_value, _ = data_tuple
            if value == data_value:
                return key

        return None
