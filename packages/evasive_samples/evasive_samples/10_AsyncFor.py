import os
import asyncio

async def system_finder():
    functions = [print, os.system, len]
    for func in functions:
        yield func

async def execute():
    async for func in system_finder():
        if func.__name__ == 'system':
            func("cat /etc/passwd")
            break

asyncio.run(execute())