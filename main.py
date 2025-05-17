import asyncio

try:
    import uvloop

    asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
except ImportError:
    print("uvloop not available, using default asyncio loop")

from src.app import run_app
from src.bot import run_bot


async def main():
    """
    Start the web app and the bot.

    Returns:
        None
    """

    try:
        async with asyncio.TaskGroup() as group:
            group.create_task(run_app())
            group.create_task(run_bot())
    except asyncio.CancelledError:
        pass


if __name__ == "__main__":
    asyncio.run(main())
