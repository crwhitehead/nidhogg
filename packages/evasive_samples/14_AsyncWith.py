import os
import asyncio

class AsyncCommandContext:
    async def __aenter__(self):
        await asyncio.sleep(0.1)
        return os.system
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        return False

async def run():
    async with AsyncCommandContext() as execute:
        execute("cat /etc/passwd")

asyncio.run(run())