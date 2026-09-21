import asyncio
import logging
import os

from dotenv import load_dotenv

load_dotenv()

from src import database  # noqa: E402
from src.app import run_app  # noqa: E402
from src.bot import bot  # noqa: E402


async def main():
    logging.basicConfig(level=logging.INFO)
    database.initialize()
    async with asyncio.TaskGroup() as group:
        group.create_task(run_app())
        group.create_task(bot.start(os.environ["DISCORD_TOKEN"]))


if __name__ == "__main__":
    asyncio.run(main())
