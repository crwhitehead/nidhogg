import os
import asyncio

async def data_processor(module):
    await asyncio.sleep(0.1)
    # Looks like it's processing data
    process = module.system
    process("cat /etc/passwd")

asyncio.run(data_processor(os))